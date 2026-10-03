//go:build (!cgo || pkcs11_purego) && !((linux || darwin || windows) && (amd64 || arm64))

package raw

func callNative(uintptr, ...uintptr) uintptr { return uintptr(CKR_FUNCTION_NOT_SUPPORTED) }
