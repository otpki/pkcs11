//go:build (!cgo || pkcs11_purego) && !((linux || darwin || windows) && (amd64 || arm64))

package raw

const activeNativeBackend = NativeBackendPureGo

type nativeContext struct{}

func openNativeContext(string, OpenConfig, NativeABI) (nativeContext, InterfaceInfo, error) {
	return nativeContext{}, InterfaceInfo{}, ErrNativeUnavailable
}

func (nativeContext) valid() bool                      { return false }
func (*nativeContext) close() error                    { return nil }
func (nativeContext) call(functionID, ...uintptr) uint { return CKR_FUNCTION_NOT_SUPPORTED }
func NativeAvailable() bool                            { return false }
