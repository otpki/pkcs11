package raw

// NativeBackend identifies the native-call backend compiled into this build.
// cgo is the default when enabled. No-cgo builds use PureGo, and the
// pkcs11_purego tag can force PureGo for testing. Both backends share the same
// Ctx implementation, function inventory, and ABI layouts.
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
