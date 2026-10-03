//go:build (!cgo || pkcs11_purego) && (linux || darwin || windows) && (amd64 || arm64)

package raw

import "github.com/ebitengine/purego"

func callNative(function uintptr, arguments ...uintptr) uintptr {
	result, _, _ := purego.SyscallN(function, arguments...)
	return result
}
