//go:build (!cgo || pkcs11_purego) && !((linux || darwin || windows) && (amd64 || arm64))

package raw

type nativeLibrary uintptr

func openNativeLibrary(string) (nativeLibrary, error)           { return 0, ErrNativeUnavailable }
func lookupNativeSymbol(nativeLibrary, string) (uintptr, error) { return 0, ErrNativeUnavailable }
func closeNativeLibrary(nativeLibrary) error                    { return nil }
