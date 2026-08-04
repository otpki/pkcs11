package raw

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

// Ctx owns one dynamically loaded PKCS #11 module and the function table
// selected from that module.
//
// Ctx is deliberately independent of the native-call transport. Normal builds
// use the generated cgo bridge, while builds without cgo (or builds using the
// pkcs11_purego tag) use the PureGo transport. All Cryptoki semantics,
// structure encoding, output-buffer handling, and operation lifetime rules are
// implemented once in the shared raw package.
//
// The lifecycle is explicit:
//
//   - Open loads the shared library and selects a function table.
//   - Initialize or InitializeWithFlags calls C_Initialize.
//   - Finalize calls C_Finalize.
//   - Destroy unloads the shared library and invalidates the table.
//
// Destroy does not call Finalize automatically because initialization may be
// shared or coordinated by the managed package's process-wide module registry.
// The lifetime mutex prevents a native function pointer from racing with
// library unload.
type Ctx struct {
	mu       sync.RWMutex
	native   nativeContext
	path     string
	closed   bool
	abi      NativeABI
	selected InterfaceInfo

	// Output-buffer policy is atomic because a managed vendor module may apply a
	// compatibility policy while other calls are already in flight.
	outputNullFallback atomic.Bool
	outputInitial      atomic.Uint64
	outputMaximum      atomic.Uint64

	// active retains mechanism parameter memory for providers that keep pointers
	// between an Init call and the corresponding completion/cancellation call.
	active   activeMechanismStore
	sessions sessionHandleStore
}

// Open loads the PKCS #11 shared library at path and selects a compatible
// function table. It does not initialize the module, select a token, open a
// session, or log in.
//
// Interface versions are attempted in the order supplied by OpenConfig. When
// no requested PKCS #11 3.x interface can be selected and legacy fallback is
// enabled, Open asks the module for its C_GetFunctionList table.
func Open(path string, options ...OpenOption) (*Ctx, error) {
	if !NativeAvailable() {
		return nil, ErrNativeUnavailable
	}

	config := ResolveOpenConfig(options...)
	abi := HostNativeABI()
	native, selected, err := openNativeContext(path, config, abi)
	if err != nil {
		return nil, err
	}

	ctx := &Ctx{
		native:   native,
		path:     path,
		abi:      abi,
		selected: selected,
	}
	runtime.SetFinalizer(ctx, (*Ctx).Destroy)
	return ctx, nil
}

// New loads path using the default interface-selection policy and returns nil
// when loading or negotiation fails. Prefer Open when diagnostics matter.
func New(path string) *Ctx {
	ctx, _ := Open(path)
	return ctx
}

// Path returns the path passed to Open.
func (c *Ctx) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Interface returns metadata for the selected function table.
func (c *Ctx) Interface() InterfaceInfo {
	if c == nil {
		return InterfaceInfo{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed || !c.native.valid() {
		return InterfaceInfo{}
	}
	return c.selected
}

// Version returns the version of the selected function table.
func (c *Ctx) Version() Version { return c.Interface().Version }

// Supports reports whether the selected function-table version is at least
// version. It does not imply that a token advertises any particular mechanism.
func (c *Ctx) Supports(version Version) bool { return c.Version().AtLeast(version) }

// SetOutputBufferPolicy configures bounded compatibility behavior for native
// functions whose output size is ordinarily queried with a nil buffer.
func (c *Ctx) SetOutputBufferPolicy(policy OutputBufferPolicy) {
	if c == nil {
		return
	}
	policy = policy.normalized()
	c.outputInitial.Store(uint64(policy.InitialSize))
	c.outputMaximum.Store(uint64(policy.MaximumSize))
	c.outputNullFallback.Store(policy.RejectNullProbe)
}

func (c *Ctx) outputBufferPolicy() OutputBufferPolicy {
	policy := OutputBufferPolicy{RejectNullProbe: c != nil && c.outputNullFallback.Load()}
	if c != nil {
		policy.InitialSize = uint(c.outputInitial.Load())
		policy.MaximumSize = uint(c.outputMaximum.Load())
	}
	return policy.normalized()
}

// Destroy invalidates the selected table and unloads the native library. It is
// safe to call repeatedly. Destroy never calls Finalize automatically.
func (c *Ctx) Destroy() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}

	c.closed = true
	c.releaseAllMechanisms()
	c.sessions.clear()
	runtime.SetFinalizer(c, nil)
	_ = c.native.close()
	c.native = nativeContext{}
	c.selected = InterfaceInfo{}
}

// locked holds a read lease over the native library. Every ABI call keeps this
// lease until the provider function returns, so Destroy cannot unload the
// function table concurrently.
func (c *Ctx) locked() (*Ctx, func(), error) {
	if c == nil {
		return nil, func() {}, ErrClosed
	}
	c.mu.RLock()
	if c.closed || !c.native.valid() {
		c.mu.RUnlock()
		return nil, func() {}, ErrClosed
	}
	return c, c.mu.RUnlock, nil
}

// call validates the generated function metadata before entering either native
// transport. A wrong argument count is a binding defect that could corrupt the
// process, so it panics before crossing the ABI boundary.
func (c *Ctx) call(id functionID, arguments ...uintptr) uint {
	if c == nil || id >= functionCount {
		return CKR_FUNCTION_NOT_SUPPORTED
	}

	metadata := functionTableMetadata[id]
	if len(arguments) != int(metadata.arguments) {
		panic(fmt.Sprintf(
			"pkcs11: internal binding for %s supplied %d arguments; want %d",
			metadata.name,
			len(arguments),
			metadata.arguments,
		))
	}
	if !c.selected.Version.AtLeast(metadata.minimum) {
		return CKR_FUNCTION_NOT_SUPPORTED
	}
	return c.native.call(id, arguments...)
}

// Initialize calls C_Initialize with CKF_OS_LOCKING_OK and nil mutex callbacks.
func (c *Ctx) Initialize() error { return c.InitializeWithFlags(CKF_OS_LOCKING_OK) }

// InitializeLegacy calls C_Initialize with a nil argument pointer.
func (c *Ctx) InitializeLegacy() error {
	ctx, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(ctx.call(functionInitialize, 0))
}

// InitializeWithFlags calls C_Initialize with zeroed callback pointers and the
// supplied flags. The structure is encoded using the same explicit ABI layout
// for both native transports.
func (c *Ctx) InitializeWithFlags(flags uint) error {
	ctx, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()

	layout := initializeArgsLayout(ctx.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, bytes, err := arena.alloc(layout.size)
	if err != nil {
		return err
	}
	ctx.abi.putULong(bytes, layout.flags, flags)
	return rv(ctx.call(functionInitialize, pointer))
}

// Finalize calls C_Finalize with a nil reserved pointer. Successful
// finalization also releases retained operation memory and session bookkeeping.
func (c *Ctx) Finalize() error {
	ctx, unlock, err := c.locked()
	if err != nil {
		return err
	}
	callErr := rv(ctx.call(functionFinalize, 0))
	unlock()
	if callErr == nil {
		ctx.releaseAllMechanisms()
		ctx.sessions.clear()
	}
	return callErr
}

type initializeLayout struct {
	flags int
	size  int
}

func initializeArgsLayout(abi NativeABI) initializeLayout {
	builder := newNativeLayoutBuilder(abi)
	for range 4 {
		builder.addPointer()
	}
	layout := initializeLayout{flags: builder.addULong()}
	builder.addPointer()
	layout.size = builder.size()
	return layout
}
