//go:build (!cgo || pkcs11_purego) && (linux || darwin) && (amd64 || arm64)

package raw

import "github.com/ebitengine/purego"

type nativeLibrary uintptr

func openNativeLibrary(path string) (nativeLibrary, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	return nativeLibrary(handle), err
}

func lookupNativeSymbol(library nativeLibrary, name string) (uintptr, error) {
	return purego.Dlsym(uintptr(library), name)
}

func closeNativeLibrary(library nativeLibrary) error {
	if library == 0 {
		return nil
	}
	return purego.Dlclose(uintptr(library))
}
