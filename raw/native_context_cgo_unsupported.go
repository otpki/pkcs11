//go:build cgo && !pkcs11_purego && !((linux || darwin || windows) && (amd64 || arm64))

package raw

const activeNativeBackend = NativeBackendCGO

type nativeContext struct{}

func openNativeContext(string, OpenConfig, NativeABI) (nativeContext, InterfaceInfo, error) {
	return nativeContext{}, InterfaceInfo{}, ErrNativeUnavailable
}

func (*nativeContext) valid() bool                      { return false }
func (*nativeContext) close() error                     { return nil }
func (*nativeContext) call(functionID, ...uintptr) uint { return CKR_FUNCTION_NOT_SUPPORTED }

// NativeAvailable reports that the cgo transport has not been validated for
// this operating-system and architecture combination.
func NativeAvailable() bool { return false }
