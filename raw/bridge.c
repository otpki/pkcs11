//go:build cgo && !pkcs11_purego && (linux || darwin || windows) && (amd64 || arm64)

#include "internal/cryptoki/bridge.c"
