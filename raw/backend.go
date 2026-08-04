package raw

// NativeBackend identifies the implementation used to load and call native
// PKCS #11 modules in the current build.
//
// Backend selection is compile-time and automatic:
//   - when cgo is enabled, the cgo bridge is selected by default;
//   - when cgo is disabled, the PureGo backend is selected automatically; and
//   - the pkcs11_purego build tag forces PureGo even when cgo is available.
//
// Ctx and every Cryptoki operation are implemented once. The selected backend
// supplies only native loading, allocation, and function-pointer invocation.
// both consume the same pinned OASIS PKCS #11 3.2 function table and
// explicit ABI layouts.
type NativeBackend string

const (
	// NativeBackendCGO is the default transport for cgo-enabled builds. It
	// allocates native call memory with the C allocator and invokes a generated
	// typed dispatcher derived from the pinned OASIS function declarations.
	NativeBackendCGO NativeBackend = "cgo"

	// NativeBackendPureGo is the no-cgo fallback implemented with
	// github.com/ebitengine/purego and explicit native structure layouts.
	NativeBackendPureGo NativeBackend = "purego"
)

// ActiveNativeBackend returns the native ABI backend compiled into this build.
// The value is process-wide. It does not vary between Ctx or Client instances.
func ActiveNativeBackend() NativeBackend { return activeNativeBackend }
