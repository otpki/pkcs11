//go:build cgo && !pkcs11_purego && (linux || darwin || windows) && (amd64 || arm64)

package raw

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// allocateNativeBlock returns zeroed C-owned memory. Shared marshalling writes
// explicit Cryptoki layouts into the byte view, while C ownership guarantees
// that no Go pointer graph is retained by a cgo call or multipart operation.
func allocateNativeBlock(length int) (nativeBlock, error) {
	if length <= 0 {
		return nativeBlock{}, nil
	}
	pointer := C.calloc(1, C.size_t(length))
	if pointer == nil {
		return nativeBlock{}, fmt.Errorf("pkcs11: allocate %d native bytes", length)
	}
	address := uintptr(pointer)
	bytes := unsafe.Slice((*byte)(pointer), length)
	return nativeBlock{
		pointer: address,
		bytes:   bytes,
		release: func() { C.free(pointer) },
	}, nil
}
