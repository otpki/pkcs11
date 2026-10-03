//go:build cgo && !pkcs11_purego && !((linux || darwin || windows) && (amd64 || arm64))

package raw

func allocateNativeBlock(int) (nativeBlock, error) {
	return nativeBlock{}, ErrNativeUnavailable
}
