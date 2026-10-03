//go:build !cgo || pkcs11_purego

package raw

import (
	"runtime"
	"unsafe"
)

// allocateNativeBlock returns pinned Go byte memory. The block contains no Go
// pointer-typed fields; explicit pointer relocations are written as native
// integer bytes only after every target allocation has been pinned.
func allocateNativeBlock(length int) (nativeBlock, error) {
	if length <= 0 {
		return nativeBlock{}, nil
	}
	buffer := make([]byte, length)
	pinner := new(runtime.Pinner)
	pinner.Pin(&buffer[0])
	return nativeBlock{
		pointer: uintptr(unsafe.Pointer(&buffer[0])),
		bytes:   buffer,
		release: func() {
			pinner.Unpin()
			runtime.KeepAlive(buffer)
		},
	}, nil
}
