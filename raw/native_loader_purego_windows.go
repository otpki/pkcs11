//go:build (!cgo || pkcs11_purego) && windows && (amd64 || arm64)

package raw

import "syscall"

type nativeLibrary syscall.Handle

func openNativeLibrary(path string) (nativeLibrary, error) {
	handle, err := syscall.LoadLibrary(path)
	return nativeLibrary(handle), err
}

func lookupNativeSymbol(library nativeLibrary, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(library), name)
}

func closeNativeLibrary(library nativeLibrary) error {
	if library == 0 {
		return nil
	}
	return syscall.FreeLibrary(syscall.Handle(library))
}
