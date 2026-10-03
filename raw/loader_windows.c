//go:build cgo && !pkcs11_purego && windows && (amd64 || arm64)

#include "internal/cryptoki/loader_windows.c"
