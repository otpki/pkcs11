//go:build cgo && !pkcs11_purego && (linux || darwin) && (amd64 || arm64)

#include "internal/cryptoki/loader_unix.c"
