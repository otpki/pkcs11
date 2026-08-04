package pkcs11

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/otpki/pkcs11/raw"
)

// moduleRef is the process-wide owner of one loaded PKCS #11 shared library.
//
// PKCS #11 initialization is generally process-global for a module, even when
// several Clients select different slots from that module. moduleRef therefore
// reference-counts users and coordinates initialization, finalization, calls,
// multipart-operation leases, and recovery across all of those Clients.
//
// Locks must be acquired in this order whenever more than one is needed:
// lifecycle, leases, calls, serialized. Preserving that order prevents a normal
// call, reinitialization, and final release from deadlocking one another.
type moduleRef struct {
	// key is the immutable process-wide identity supplied by ModuleSource.
	key string
	// path is a human-readable local path or remote target description.
	path string
	// source can reopen the same immutable logical module during initial load.
	source ModuleSource
	// raw owns the local or remote logical module and selected interface.
	raw raw.Module

	// lifecycle serializes initialization, recovery policy updates, and final
	// release. It does not protect ordinary calls by itself.
	lifecycle sync.Mutex
	// leases protects complete managed operations, including the gaps between
	// multipart Cryptoki calls. Reinitialization and unload take the write lock
	// so they cannot invalidate a session between (for example) SignInit and
	// Sign.
	leases sync.RWMutex
	// calls prevents unloading or reinitializing the raw module while a native
	// call is executing. Unlike leases, it covers only the individual call.
	calls sync.RWMutex
	// serialized is used only for modules whose initialization or adapter plan
	// requires process-wide call serialization.
	serialized sync.Mutex

	// refs counts managed Clients sharing this exact canonical module path.
	refs int
	// initialized records observed module state, regardless of who initialized it.
	initialized bool
	// managedInitialize is true only when this package successfully performed
	// C_Initialize and therefore owns the matching C_Finalize responsibility.
	managedInitialize bool
	// skipFinalize is sticky process-wide compatibility policy for modules that
	// cannot safely be finalized while the process remains alive.
	skipFinalize bool
	// legacyInitialize records that initialization required a nil argument.
	legacyInitialize bool
	// forceSerialize is sticky process-wide policy. It is enabled when either
	// initialization falls back to the legacy nil-argument form or any selected
	// vendor module declares that the shared native library is not safe for
	// concurrent calls. Because all Clients share one loaded library, a later
	// client may make this policy more conservative but can never relax it.
	forceSerialize bool
	// rejectNullOutputProbe is sticky process-wide output-buffer policy. The raw
	// context stores one policy per loaded library, so a client selecting another
	// slot must not disable a workaround already required by a sibling client.
	rejectNullOutputProbe bool

	// generation changes whenever module-level recovery invalidates pooled
	// sessions and cached handles. A session created under an older generation
	// must not be reused.
	generation atomic.Uint64
	// closed is written only while the lifecycle, lease, and call write locks
	// exclude all new and in-flight work.
	closed bool
}

// modules ensures that one physical shared library is loaded and initialized at
// most once by the managed driver for each canonical path.
var modules = struct {
	sync.Mutex
	byPath map[string]*moduleRef
}{byPath: make(map[string]*moduleRef)}

// acquireModule returns a reference-counted, initialized module. The registry
// lock deliberately covers lookup, load, and initial initialization so two
// concurrent Open calls cannot initialize separate handles for the same path.
func acquireModule(ctx context.Context, source ModuleSource) (*moduleRef, error) {
	if err := validateModuleSource(source); err != nil {
		return nil, err
	}
	key := source.RegistryKey()
	path := source.String()
	modules.Lock()
	defer modules.Unlock()
	if existing := modules.byPath[key]; existing != nil && !existing.closed {
		// A prior recovery attempt may have left the shared handle loaded but not
		// initialized. Repair it before handing out another reference.
		if !existing.initialized {
			if err := existing.ensureInitialized(false, true); err != nil {
				return nil, fmt.Errorf("pkcs11: initialize shared module %q: %w", path, err)
			}
		}
		existing.refs++
		return existing, nil
	}
	rawModule, err := source.OpenModule(ctx)
	if err != nil {
		return nil, err
	}
	module := &moduleRef{key: key, path: path, source: source, raw: rawModule, refs: 1}
	module.generation.Store(1)
	err = module.initialize(false, true)
	if err == nil {
		module.initialized = true
		module.managedInitialize = true
	} else if raw.IsError(err, raw.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		// Another library user initialized the process-global module. We can use
		// it, but must not later claim ownership by calling C_Finalize.
		module.initialized = true
	} else {
		rawModule.Destroy()
		return nil, fmt.Errorf("pkcs11: initialize module %q: %w", path, err)
	}
	modules.byPath[key] = module
	return module, nil
}

// ensureInitialized initializes an existing shared module under the complete
// lifecycle lock set. It is safe to call when the caller does not know whether
// another Client or recovery path has already initialized the module.
func (m *moduleRef) ensureInitialized(forceLegacy, allowFallback bool) error {
	// Exclusive leases stop between-call gaps in multipart operations, while
	// exclusive calls wait for any native call already in progress.
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.leases.Lock()
	defer m.leases.Unlock()
	m.calls.Lock()
	defer m.calls.Unlock()
	if m.closed {
		return fmt.Errorf("pkcs11: module is closed")
	}
	if m.initialized {
		return nil
	}
	err := m.initialize(forceLegacy, allowFallback)
	if err == nil {
		m.initialized = true
		m.managedInitialize = true
		return nil
	}
	if raw.IsError(err, raw.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		m.initialized = true
		return nil
	}
	return err
}

// initializationFallbackError reports errors that commonly mean a legacy
// module rejected CK_C_INITIALIZE_ARGS rather than failing for an unrelated
// reason. Only these errors permit the nil-argument compatibility retry.
func initializationFallbackError(err error) bool {
	return raw.IsError(err, raw.CKR_CANT_LOCK) ||
		raw.IsError(err, raw.CKR_NEED_TO_CREATE_THREADS) ||
		raw.IsError(err, raw.CKR_ARGUMENTS_BAD)
}

// initialize prefers the PKCS #11 locking contract. Some older vendor modules
// only accept a nil C_Initialize argument; when that compatibility path is
// used, all calls through the module are serialized by the managed driver.
func (m *moduleRef) initialize(forceLegacy, allowFallback bool) error {
	if forceLegacy {
		err := m.raw.InitializeLegacy()
		if err == nil {
			m.legacyInitialize = true
			m.forceSerialize = true
		}
		return err
	}
	err := m.raw.Initialize()
	if err == nil || raw.IsError(err, raw.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return err
	}
	if !allowFallback || !initializationFallbackError(err) {
		return err
	}
	legacyErr := m.raw.InitializeLegacy()
	if legacyErr != nil {
		return fmt.Errorf("OS-locking initialization failed: %w; legacy initialization failed: %w", err, legacyErr)
	}
	m.legacyInitialize = true
	m.forceSerialize = true
	return nil
}

// releaseModule drops one Client reference and tears the module down after the
// final reference is gone. Teardown is performed while the registry still owns
// the path, preventing a concurrent Open from racing a new load against unload.
func releaseModule(module *moduleRef) error {
	if module == nil {
		return nil
	}
	modules.Lock()
	defer modules.Unlock()
	if module.refs > 0 {
		module.refs--
	}
	if module.refs != 0 {
		return nil
	}
	delete(modules.byPath, module.key)

	// Wait for complete managed operations first, then individual calls. This
	// ensures no session can be between Init and Final when the library unloads.
	module.lifecycle.Lock()
	defer module.lifecycle.Unlock()
	module.leases.Lock()
	defer module.leases.Unlock()
	module.calls.Lock()
	defer module.calls.Unlock()
	module.closed = true
	var err error
	if module.initialized && module.managedInitialize && !module.skipFinalize {
		if finalizeErr := module.raw.Finalize(); finalizeErr != nil && !raw.IsError(finalizeErr, raw.CKR_CRYPTOKI_NOT_INITIALIZED) {
			err = fmt.Errorf("pkcs11: finalize module: %w", finalizeErr)
		}
	}
	module.raw.Destroy()
	return err
}

// execute runs one native module call under unload protection and any required
// process-wide serialization. Callers that span multiple native calls must also
// hold a lease for the complete operation.
func (m *moduleRef) execute(ctx context.Context, plan behaviorPlan, fn func(raw.Module) error) error {
	if m == nil || m.raw == nil {
		return fmt.Errorf("pkcs11: module is closed")
	}
	m.calls.RLock()
	defer m.calls.RUnlock()
	if m.closed {
		return fmt.Errorf("pkcs11: module is closed")
	}
	if m.forceSerialize || plan.module.serializeCalls {
		m.serialized.Lock()
		defer m.serialized.Unlock()
	}
	if contextual, ok := m.raw.(raw.ContextualModule); ok {
		return contextual.WithContext(ctx, fn)
	}
	return fn(m.raw)
}

// acquireLease prevents reinitialization and unload for the full duration of a
// managed operation, including time spent between multipart Cryptoki calls. The
// caller must pair a successful acquisition with releaseLease.
func (m *moduleRef) acquireLease() error {
	if m == nil || m.raw == nil {
		return fmt.Errorf("pkcs11: module is closed")
	}
	m.leases.RLock()
	if m.closed {
		m.leases.RUnlock()
		return fmt.Errorf("pkcs11: module is closed")
	}
	return nil
}

// releaseLease releases a successful acquireLease call.
func (m *moduleRef) releaseLease() {
	if m != nil {
		m.leases.RUnlock()
	}
}

// reinitialize is intentionally conservative. It never unloads the vendor
// library while it may own background threads. Existing pooled sessions are
// invalidated by bumping generation and are closed lazily.
func (m *moduleRef) reinitialize(plan behaviorPlan) error {
	if m == nil {
		return fmt.Errorf("pkcs11: module is closed")
	}
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.leases.Lock()
	defer m.leases.Unlock()
	m.calls.Lock()
	defer m.calls.Unlock()
	if m.closed {
		return fmt.Errorf("pkcs11: module is closed")
	}
	if m.forceSerialize || plan.module.serializeCalls {
		m.serialized.Lock()
		defer m.serialized.Unlock()
	}
	if m.initialized && m.managedInitialize && !m.skipFinalize && !plan.module.skipFinalize {
		// Recovery is best-effort with respect to the old state. Initialization
		// below is authoritative; many modules return useful errors only there.
		_ = m.raw.Finalize()
	}
	err := m.initialize(m.legacyInitialize || plan.module.legacyInit, true)
	if err != nil && !raw.IsError(err, raw.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return fmt.Errorf("pkcs11: reinitialize module: %w", err)
	}
	m.initialized = true
	m.generation.Add(1)
	return nil
}

// applyPlan promotes token-specific adapter requirements that affect the shared
// process-wide module lifecycle. Such policy may only become more conservative.
func (m *moduleRef) applyPlan(plan behaviorPlan) {
	if m == nil {
		return
	}
	m.lifecycle.Lock()
	m.applyPlanLocked(plan)
	m.lifecycle.Unlock()
}

// applyPlanLocked applies process-wide lifecycle behavior while the caller
// already owns m.lifecycle. Keeping this separate prevents refresh from
// recursively acquiring the lifecycle mutex.
func (m *moduleRef) applyPlanLocked(plan behaviorPlan) {
	if plan.module.skipFinalize {
		// Finalization policy is process-wide for one loaded module. Once any
		// selected vendor module requires skipping C_Finalize, keep that policy
		// until the native library is unloaded.
		m.skipFinalize = true
	}
	if plan.module.serializeCalls {
		// Thread-safety is a property of the loaded native library, not of one
		// token. Promote it to the registry entry so every Client sharing this
		// module uses the same serialization lock.
		m.forceSerialize = true
	}
	if plan.module.legacyInit {
		// The initial standards-first C_Initialize call happens before a token can
		// be fingerprinted. Its built-in fallback handles modules that reject
		// CK_C_INITIALIZE_ARGS. Once a selected vendor module explicitly declares
		// legacy initialization, retain that fact for recovery and serialize calls
		// because the module did not opt into CKF_OS_LOCKING_OK.
		m.legacyInitialize = true
		m.forceSerialize = true
	}
	if plan.buffers.rejectNullProbe && !m.rejectNullOutputProbe {
		// Output-buffer policy also lives on the one shared raw context. It is
		// therefore monotonic: one slot requiring a real-buffer size probe makes
		// that safer fallback apply to all Clients using this module.
		m.rejectNullOutputProbe = true
		if m.raw != nil {
			m.raw.SetOutputBufferPolicy(raw.OutputBufferPolicy{RejectNullProbe: true})
		}
	}
}

// bumpGeneration invalidates generation-tagged sessions and cache entries
// without synchronously walking every pool and cache data structure.
func (m *moduleRef) bumpGeneration() uint64 {
	if m == nil {
		return 0
	}
	return m.generation.Add(1)
}

// currentGeneration returns the epoch against which sessions and cached handles
// should be validated.
func (m *moduleRef) currentGeneration() uint64 {
	if m == nil {
		return 0
	}
	return m.generation.Load()
}
