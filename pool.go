package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// poolConfig is the normalized capacity and idle-retirement policy used by one
// read-only or read/write session pool. Values are resolved against both the
// token-reported limits and the selected adapter before the pool is created.
type poolConfig struct {
	// MinSessions is the number of handles Warm attempts to keep available.
	MinSessions int
	// MaxSessions bounds checked-out sessions and therefore native handles.
	MaxSessions int
	// IdleTimeout retires a handle before reuse after this period of inactivity.
	IdleTimeout time.Duration
	// MaxLifetime retires a handle after a bounded wall-clock lifetime.
	MaxLifetime time.Duration
	// MaxOperations retires a handle after this many managed calls.
	MaxOperations uint64
}

// defaultPoolConfig converts the public SessionConfig defaults into the
// internal representation used after token discovery.
func defaultPoolConfig() poolConfig {
	defaults := DefaultSessionConfig()
	return poolConfig{MinSessions: defaults.Min, MaxSessions: defaults.Max, IdleTimeout: defaults.IdleTimeout}
}

// sessionPoolConfig contains the fully resolved dependencies and policy needed
// to construct a sessionPool. It is assembled by Open after token selection and
// adapter detection, so the pool never performs discovery itself.
type sessionPoolConfig struct {
	// Owner supplies shared login coordination and cache invalidation.
	Owner *Client
	// Module is the process-wide loaded-module reference used by every handle.
	Module *moduleRef
	// Device contains the selected slot, capabilities, and private behavior plan.
	Device Device
	// Limiter bounds native handles across both the read-only and read/write pools.
	Limiter *sessionLimiter
	// ReadWrite selects CKF_RW_SESSION and the token's read/write session limit.
	ReadWrite bool
	// Async requests CKF_ASYNC_SESSION and requires advertised token support.
	Async bool
	// UserType and Username identify the configured login identity.
	UserType uint
	Username string
	// PIN obtains credentials only when a login attempt is actually required.
	PIN PINProvider
	// LoginMode controls automatic login and manual activation behavior.
	LoginMode LoginMode
	// ProtectedAuthenticationPath permits login without application PIN bytes.
	ProtectedAuthenticationPath bool
	Pool                        poolConfig
	Hooks                       Hooks
}

// pooledSession is an idle or checked-out native session together with the
// module generation and optional pinned-thread worker that own it. A handle may
// be reused only while its generation matches the module generation.
type pooledSession struct {
	handle raw.SessionHandle
	// generation identifies the module initialization that created handle.
	generation uint64
	// lastUsed is meaningful only while the item is in the idle queue.
	lastUsed time.Time
	// worker is non-nil when all calls for this handle must share one OS thread.
	worker   *sessionWorker
	openedAt time.Time
	uses     uint64
	// authentication identifies infrastructure-owned session-scoped login state.
	// It is retained only while this exact native handle remains healthy.
	authentication string
}

// sessionPool bounds native session creation, reuses healthy idle sessions,
// coordinates login, and keeps checked-out operations protected by a module
// lease. Separate instances are maintained for read-only and read/write use.
type sessionPool struct {
	owner         *Client
	module        *moduleRef
	deviceMu      sync.RWMutex
	device        Device
	flags         uint
	readWrite     bool
	userType      uint
	username      string
	pin           PINProvider
	loginMode     LoginMode
	protectedPath bool
	max           int
	min           int
	idleTimeout   time.Duration
	maxLifetime   time.Duration
	maxOperations uint64
	// sem is a counting semaphore for checked-out leases, not merely opened
	// handles. Holding a token also implies holding a module operation lease.
	sem chan struct{}
	// idle stores reusable handles; its capacity is the resolved pool maximum.
	idle         chan pooledSession
	closed       atomic.Bool
	deactivating atomic.Bool
	// activeLogin gates automatic login in manual activation mode.
	activeLogin atomic.Bool
	// mu protects opened and active. drained uses the same mutex.
	mu      sync.Mutex
	drained *sync.Cond
	// opened counts every native handle owned by the pool.
	opened int
	// active counts handles currently represented by sessionLease values.
	active  int
	hooks   Hooks
	limiter *sessionLimiter
}

// sessionLease is the exclusive, short-lived ownership token returned by
// sessionPool.Acquire. Closing the lease either returns the native session to the
// idle queue or destroys it when it is stale, broken, or the pool is closing.
type sessionLease struct {
	pool   *sessionPool
	handle raw.SessionHandle
	// generation must still match the module when the lease is returned.
	generation uint64
	// ctx is the acquisition context used by managed calls and hooks.
	//nolint:containedctx // A lease owns its acquisition context as the fallback for ctx-less calls.
	ctx context.Context
	// operation and attempt are populated by Client.withSession for observability.
	operation string
	attempt   int
	// broken forces native close instead of reuse.
	broken atomic.Bool
	closed atomic.Bool
	once   sync.Once
	// closeErr is retained so repeated Close calls return the same result.
	closeErr       error
	worker         *sessionWorker
	authentication string
	openedAt       time.Time
	uses           atomic.Uint64
}

// Raw returns the underlying ABI module. Prefer the managed sessionLease methods;
// this escape hatch bypasses per-call hooks, automatic broken-session marking,
// and any locked-OS-thread executor required by the selected HSM adapter. A
// direct call using Handle may therefore violate a vendor's session-affinity
// requirement. It is retained for vendor extensions that have not yet been
// modeled; use sessionLease.DoRaw to preserve managed execution semantics.
func (s *sessionLease) Raw() raw.Module {
	if s == nil || s.pool == nil || s.pool.module == nil {
		return nil
	}
	return s.pool.module.raw
}

// DoRaw executes an unmodeled raw operation using this session's managed
// module serialization and OS-thread-affinity policy. Returning a PKCS #11
// session/device error marks the session broken when the managed retry
// classifier says that the native handle cannot safely be reused.
//
//nolint:contextcheck // Nil callers intentionally fall back to the lease's context.
func (s *sessionLease) DoRaw(ctx context.Context, fn func(raw.Module, raw.SessionHandle) error) error {
	if s == nil || s.pool == nil || s.closed.Load() {
		return errors.New("pkcs11: session is closed")
	}
	if fn == nil {
		return errors.New("pkcs11: nil raw callback")
	}
	if ctx == nil {
		ctx = s.Context()
	}
	err := s.pool.execute(ctx, s.worker, func(module raw.Module) error {
		return fn(module, s.handle)
	})
	switch classifyDeviceError(s.currentDevice(), err, false) {
	case RecoveryReplaceSession, RecoveryReinitialize, RecoveryRediscover:
		s.MarkBroken()
	}
	return err
}

// Handle returns the native session handle owned by this lease. The handle is
// valid only until Close returns and must not be retained or used concurrently.
func (s *sessionLease) Handle() raw.SessionHandle {
	if s == nil {
		return 0
	}
	return s.handle
}

// currentDevice returns the pool's latest internal device snapshot. Callers that
// expose the value outside the driver must clone it first.
func (s *sessionLease) currentDevice() Device {
	if s == nil || s.pool == nil {
		return Device{}
	}
	return s.pool.currentDevice()
}

// Device returns an independent snapshot of the selected token and adapter.
func (s *sessionLease) Device() Device { return cloneDevice(s.currentDevice()) }

// ReadWrite reports whether the lease was acquired from the read/write pool.
func (s *sessionLease) ReadWrite() bool { return s != nil && s.pool != nil && s.pool.readWrite }

// MarkBroken prevents the native handle from being returned to the idle pool.
// It is safe to call more than once.
func (s *sessionLease) MarkBroken() {
	if s != nil {
		s.broken.Store(true)
	}
}

// Context returns the acquisition context associated with this lease. A
// background context is returned for a nil lease or nil stored context.
func (s *sessionLease) Context() context.Context {
	if s == nil || s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// Close releases exclusive ownership of the lease. Healthy sessions are pooled;
// broken, stale, or closing sessions are closed natively. Close is idempotent.
func (s *sessionLease) Close(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return nil
	}
	s.once.Do(func() {
		s.closed.Store(true)
		s.closeErr = s.pool.release(ctx, pooledSession{handle: s.handle, generation: s.generation, lastUsed: time.Now(), worker: s.worker, authentication: s.authentication, openedAt: s.openedAt, uses: s.uses.Load()}, s.broken.Load())
	})
	return s.closeErr
}

// newSessionPool resolves configured, adapter, and token limits and constructs a
// pool without opening native sessions. Sessions are created lazily unless Warm
// or Activate is called.
func newSessionPool(config sessionPoolConfig) (*sessionPool, error) {
	if config.Module == nil {
		return nil, errors.New("pkcs11: session pool module is required")
	}
	if config.Pool == (poolConfig{}) {
		config.Pool = defaultPoolConfig()
	}
	// Resolve the maximum in descending order of application intent, adapter
	// safety limit, and the driver's conservative fallback.
	maxSessions := config.Pool.MaxSessions
	if maxSessions <= 0 {
		maxSessions = config.Device.plan.sessions.max
	}
	if maxSessions <= 0 {
		maxSessions = 16
	}
	// Token limits are authoritative when available. PKCS #11 uses zero or
	// CK_UNAVAILABLE_INFORMATION when a useful bound is not reported.
	tokenMax := config.Device.Fingerprint.Token.MaxSessionCount
	if config.ReadWrite && config.Device.Fingerprint.Token.MaxRwSessionCount != 0 && config.Device.Fingerprint.Token.MaxRwSessionCount != raw.CK_UNAVAILABLE_INFORMATION {
		tokenMax = config.Device.Fingerprint.Token.MaxRwSessionCount
	}
	if tokenMax != 0 && tokenMax != raw.CK_UNAVAILABLE_INFORMATION && uint(maxSessions) > tokenMax {
		maxSessions = int(tokenMax)
	}
	if config.Device.plan.sessions.forceSerial {
		// Some smart-card and legacy modules cannot safely support more than one
		// live session even when their token metadata claims otherwise.
		maxSessions = 1
	}
	if maxSessions < 1 {
		maxSessions = 1
	}
	minSessions := min(max(config.Pool.MinSessions, 0), maxSessions)
	flags := raw.CKF_SERIAL_SESSION
	if config.ReadWrite {
		flags |= raw.CKF_RW_SESSION
	}
	if config.Async {
		if !config.Device.Capabilities.AsyncSessions {
			return nil, errors.New("pkcs11: token does not advertise asynchronous sessions")
		}
		flags |= raw.CKF_ASYNC_SESSION
	}
	userType := config.UserType
	mode := config.LoginMode
	if mode == "" {
		mode = LoginLazy
	}
	pool := &sessionPool{owner: config.Owner, module: config.Module, device: config.Device, flags: flags, readWrite: config.ReadWrite, userType: userType, username: config.Username, pin: config.PIN, loginMode: mode, protectedPath: config.ProtectedAuthenticationPath, max: maxSessions, min: minSessions, idleTimeout: config.Pool.IdleTimeout, maxLifetime: config.Pool.MaxLifetime, maxOperations: config.Pool.MaxOperations, sem: make(chan struct{}, maxSessions), idle: make(chan pooledSession, maxSessions), hooks: config.Hooks, limiter: config.Limiter}
	pool.drained = sync.NewCond(&pool.mu)
	if mode == LoginLazy || mode == LoginEager {
		pool.activeLogin.Store(true)
	}
	return pool, nil
}

// currentDevice returns the adapter/device snapshot currently used for new calls.
func (p *sessionPool) currentDevice() Device {
	p.deviceMu.RLock()
	defer p.deviceMu.RUnlock()
	return p.device
}

// SetDevice installs a rediscovered device snapshot and invalidates all idle
// sessions because their adapter plan or slot generation may no longer apply.
func (p *sessionPool) SetDevice(ctx context.Context, device Device) {
	p.deviceMu.Lock()
	p.device = device
	p.deviceMu.Unlock()
	p.Invalidate(ctx)
}

// MaxSessions returns the resolved maximum number of concurrently leased
// sessions for this pool.
func (p *sessionPool) MaxSessions() int { return p.max }

// OpenedSessions returns the number of native handles currently owned by the
// pool, including both idle and checked-out sessions.
func (p *sessionPool) OpenedSessions() int { p.mu.Lock(); defer p.mu.Unlock(); return p.opened }

// ActiveSessions returns the number of sessions currently checked out by callers.
func (p *sessionPool) ActiveSessions() int { p.mu.Lock(); defer p.mu.Unlock(); return p.active }

// Activate enables automatic login for manual mode and ensures at least one
// usable session exists, or the configured minimum when it is greater than one.
func (p *sessionPool) Activate(ctx context.Context) error {
	if p == nil || p.closed.Load() {
		return errors.New("pkcs11: session pool is closed")
	}
	p.activeLogin.Store(true)
	target := max(p.min, 1)
	return p.warm(ctx, target)
}

// Warm opens the configured minimum number of sessions and returns them to the idle
// pool. Unlike Activate, it does not change manual activation state.
func (p *sessionPool) Warm(ctx context.Context) error {
	if p == nil || p.closed.Load() {
		return errors.New("pkcs11: session pool is closed")
	}
	return p.warm(ctx, p.min)
}

// warm checks out target distinct sessions before returning any of them. This
// guarantees that the requested number of native handles was actually opened.
func (p *sessionPool) warm(ctx context.Context, target int) error {
	if target <= 0 {
		return nil
	}
	if target > p.max {
		target = p.max
	}
	sessions := make([]*sessionLease, 0, target)
	for len(sessions) < target {
		s, err := p.Acquire(ctx)
		if err != nil {
			for _, opened := range sessions {
				_ = opened.Close(ctx)
			}
			return err
		}
		sessions = append(sessions, s)
	}
	var errs []error
	for _, s := range sessions {
		if err := s.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// beginDeactivate prevents new leases and disables automatic login while a
// Client coordinates one token-wide logout across both pools.
func (p *sessionPool) beginDeactivate() bool {
	if p == nil {
		return false
	}
	wasActive := p.activeLogin.Load()
	p.deactivating.Store(true)
	p.activeLogin.Store(false)
	return wasActive
}

// endDeactivate allows public or manually authenticated use again after the
// coordinated deactivation step completes. Automatic login remains disabled.
func (p *sessionPool) endDeactivate(restoreAutomaticLogin bool) {
	if p == nil {
		return
	}
	if restoreAutomaticLogin {
		p.activeLogin.Store(true)
	}
	p.deactivating.Store(false)
}

// waitDrained waits until all checked-out leases return. It uses a bounded poll
// so context cancellation is observed even though sync.Cond has no context API.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func (p *sessionPool) waitDrained(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		active := p.active
		p.mu.Unlock()
		if active == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// takeIdleForDeactivate removes one idle native session and acquires the module
// lease needed to use it. The returned cleanup closes the handle and releases
// the module lease; it never puts the session back into the pool.
func (p *sessionPool) takeIdleForDeactivate(ctx context.Context) (pooledSession, func() error, bool, error) {
	if p == nil {
		return pooledSession{}, nil, false, nil
	}
	select {
	case item := <-p.idle:
		if err := p.module.acquireLease(); err != nil {
			_ = p.closeHandle(ctx, item)
			return pooledSession{}, nil, false, err
		}
		cleanup := func() error {
			err := p.closeHandle(ctx, item)
			p.module.releaseLease()
			return err
		}
		return item, cleanup, true, nil
	default:
		return pooledSession{}, nil, false, nil
	}
}

// Acquire waits for pool capacity, obtains a module operation lease, and returns
// exclusive ownership of a healthy session. The caller must always close the
// returned lease, including on operation failure.
func (p *sessionPool) Acquire(ctx context.Context) (*sessionLease, error) {
	if p == nil || p.closed.Load() {
		return nil, errors.New("pkcs11: session pool is closed")
	}
	if p.deactivating.Load() {
		return nil, errors.New("pkcs11: session pool is deactivating")
	}
	// Reserve caller-visible concurrency before acquiring the module lease. This
	// prevents an unbounded number of goroutines from waiting inside the module.
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.closed.Load() || p.deactivating.Load() {
		<-p.sem
		if p.deactivating.Load() {
			return nil, errors.New("pkcs11: session pool is deactivating")
		}
		return nil, errors.New("pkcs11: session pool is closed")
	}
	if err := p.module.acquireLease(); err != nil {
		<-p.sem
		return nil, err
	}
	releaseLease := true
	defer func() {
		if releaseLease {
			p.module.releaseLease()
		}
	}()
	generation := p.module.currentGeneration()
	var item pooledSession
	for {
		// Discard stale and expired handles before exposing them to a caller. A
		// stale handle belongs to an earlier C_Initialize generation.
		select {
		case item = <-p.idle:
			if item.generation != generation ||
				(p.idleTimeout > 0 && time.Since(item.lastUsed) > p.idleTimeout) ||
				(p.maxLifetime > 0 && !item.openedAt.IsZero() && time.Since(item.openedAt) > p.maxLifetime) ||
				(p.maxOperations > 0 && item.uses >= p.maxOperations) {
				_ = p.closeHandle(ctx, item)
				continue
			}
		default:
			var err error
			item, err = p.openHandle(ctx, true)
			if err != nil {
				<-p.sem
				return nil, err
			}
			item.generation = generation
		}
		break
	}
	p.mu.Lock()
	if p.closed.Load() || p.deactivating.Load() {
		p.mu.Unlock()
		_ = p.closeHandle(ctx, item)
		<-p.sem
		if p.deactivating.Load() {
			return nil, errors.New("pkcs11: session pool is deactivating")
		}
		return nil, errors.New("pkcs11: session pool is closed")
	}
	p.active++
	p.mu.Unlock()
	releaseLease = false
	lease := &sessionLease{pool: p, handle: item.handle, generation: item.generation, ctx: ctx, worker: item.worker, authentication: item.authentication, openedAt: item.openedAt}
	lease.uses.Store(item.uses)
	return lease, nil
}

// execute applies module-wide serialization and, when present, dispatches the
// native call through the session's pinned OS-thread worker.
func (p *sessionPool) execute(ctx context.Context, worker *sessionWorker, fn func(raw.Module) error) error {
	device := p.currentDevice()
	call := func() error { return p.module.execute(ctx, device.plan, fn) }
	if worker != nil {
		return worker.do(ctx, call)
	}
	return call()
}

// openHandle creates one native session, attaches a pinned worker when required,
// records ownership, and optionally establishes the configured login state.
func (p *sessionPool) openHandle(ctx context.Context, login bool) (pooledSession, error) {
	if err := p.limiter.acquire(ctx); err != nil {
		return pooledSession{}, err
	}
	limiterOwned := true
	defer func() {
		if limiterOwned {
			p.limiter.release()
		}
	}()
	device := p.currentDevice()
	item := pooledSession{generation: p.module.currentGeneration(), openedAt: time.Now()}
	if device.plan.sessions.lockOSThread {
		item.worker = newSessionWorker()
	}
	err := p.execute(ctx, item.worker, func(module raw.Module) error {
		var err error
		item.handle, err = module.OpenSession(device.Fingerprint.SlotID, p.flags)
		return err
	})
	if err != nil {
		item.worker.close()
		return pooledSession{}, fmt.Errorf("pkcs11: open session: %w", err)
	}
	// Account for a successfully opened native handle before login. If login
	// fails, the deferred close must decrement this exact handle rather than an
	// unrelated session already in the pool.
	p.mu.Lock()
	p.opened++
	p.mu.Unlock()
	// From this point closeHandle owns and releases the shared limiter slot.
	limiterOwned = false
	ok := false
	defer func() {
		if !ok {
			_ = p.closeHandle(ctx, item)
		}
	}()
	if login && p.activeLogin.Load() && p.loginMode != LoginNone {
		if err := p.login(ctx, item, PINPurposeLogin, p.userType); err != nil {
			return pooledSession{}, err
		}
	}
	ok = true
	return item, nil
}

// login delegates to the client-wide coordinator when available so token-wide
// authentication is performed once per slot, user, and module generation.
func (p *sessionPool) login(ctx context.Context, item pooledSession, purpose PINPurpose, userType uint) error {
	if p.owner != nil && p.owner.login != nil {
		return p.owner.login.ensure(ctx, p, item, purpose, userType)
	}
	return p.loginDirect(ctx, item, purpose, userType)
}

// loginDirect obtains a short-lived Secret and performs the actual C_Login or
// C_LoginUser call. The Secret is destroyed before the method returns.
func (p *sessionPool) loginDirect(ctx context.Context, item pooledSession, purpose PINPurpose, userType uint) error {
	device := p.currentDevice()
	var pin Secret
	var err error
	if p.pin != nil {
		pin, err = p.pin(ctx, PINRequest{Purpose: purpose, SlotID: device.Fingerprint.SlotID, Token: device.Fingerprint.Token, UserType: userType, Attempt: 1, Username: p.username})
		if err != nil {
			return fmt.Errorf("pkcs11: obtain PIN: %w", err)
		}
		defer pin.Destroy()
	} else if !p.protectedPath && !device.plan.login.protectedPathOnEmptyPIN {
		return nil
	}
	err = p.execute(ctx, item.worker, func(module raw.Module) error {
		if p.username != "" {
			return module.LoginUser(item.handle, userType, pin, p.username)
		}
		return module.Login(item.handle, userType, pin)
	})
	if err != nil && !raw.IsError(err, raw.CKR_USER_ALREADY_LOGGED_IN) {
		return fmt.Errorf("pkcs11: login: %w", err)
	}
	return nil
}

// ContextLogin performs a context-specific login for an already leased session,
// as required by keys carrying CKA_ALWAYS_AUTHENTICATE.
func (p *sessionPool) ContextLogin(ctx context.Context, handle raw.SessionHandle, worker *sessionWorker) error {
	return p.login(ctx, pooledSession{handle: handle, worker: worker}, PINPurposeContextSpecific, raw.CKU_CONTEXT_SPECIFIC)
}

// release returns one checked-out session. It releases accounting and the module
// lease exactly once, then either queues or closes the native handle.
func (p *sessionPool) release(ctx context.Context, item pooledSession, broken bool) error {
	defer p.module.releaseLease()
	p.mu.Lock()
	if p.active > 0 {
		p.active--
	}
	if p.active == 0 && p.drained != nil {
		p.drained.Broadcast()
	}
	p.mu.Unlock()
	defer func() { <-p.sem }()
	if p.closed.Load() || p.deactivating.Load() || broken || item.generation != p.module.currentGeneration() ||
		(p.maxLifetime > 0 && !item.openedAt.IsZero() && time.Since(item.openedAt) > p.maxLifetime) ||
		(p.maxOperations > 0 && item.uses >= p.maxOperations) {
		// Never return a possibly invalid handle to another caller.
		return p.closeHandle(ctx, item)
	}
	item.lastUsed = time.Now()
	select {
	case p.idle <- item:
		return nil
	default:
		return p.closeHandle(ctx, item)
	}
}

// closeHandle closes the native handle on its owning worker, stops that worker,
// and updates pool ownership accounting. Already-invalid handles are harmless.
// Cleanup must complete even when the caller's context is canceled, so the
// context is detached from cancellation while keeping its values for hooks.
func (p *sessionPool) closeHandle(ctx context.Context, item pooledSession) error {
	if item.handle == 0 {
		item.worker.close()
		return nil
	}
	err := p.execute(context.WithoutCancel(ctx), item.worker, func(module raw.Module) error { return module.CloseSession(item.handle) })
	item.worker.close()
	p.mu.Lock()
	if p.opened > 0 {
		p.opened--
	}
	p.mu.Unlock()
	p.limiter.release()
	if raw.IsError(err, raw.CKR_SESSION_HANDLE_INVALID) || raw.IsError(err, raw.CKR_SESSION_CLOSED) {
		return nil
	}
	return err
}

// Invalidate closes every idle session immediately. Checked-out sessions remain
// protected by their leases and are rejected from the pool when later released.
func (p *sessionPool) Invalidate(ctx context.Context) {
	if p == nil {
		return
	}
	for {
		select {
		case item := <-p.idle:
			_ = p.closeHandle(ctx, item)
		default:
			return
		}
	}
}

// Close prevents new acquisitions, closes idle handles, and waits for every
// checked-out lease to return before reporting completion. It is idempotent.
func (p *sessionPool) Close(ctx context.Context) error {
	if p == nil || !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	var errs []error
	for {
		select {
		case item := <-p.idle:
			if err := p.closeHandle(ctx, item); err != nil {
				errs = append(errs, err)
			}
		default:
			// Checked-out sessions own native handles and may hold multipart
			// Cryptoki state. Wait for those leases to return before the client
			// releases and potentially unloads the process-wide module.
			p.mu.Lock()
			for p.active > 0 {
				p.drained.Wait()
			}
			p.mu.Unlock()
			// A session racing with Close is closed by release rather than put
			// back into the idle queue, so there is nothing else to drain here.
			return errors.Join(errs...)
		}
	}
}
