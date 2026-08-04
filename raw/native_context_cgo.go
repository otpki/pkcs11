//go:build cgo && !pkcs11_purego && (linux || darwin || windows) && (amd64 || arm64)

package raw

/*
#cgo CFLAGS: -std=c11 -I${SRCDIR}/internal/cryptoki
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const activeNativeBackend = NativeBackendCGO

type nativeContext struct {
	bridge *C.p11x_ctx
}

func openNativeContext(path string, config OpenConfig, _ NativeABI) (nativeContext, InterfaceInfo, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	errorBuffer := make([]byte, 1024)
	bridge := C.p11x_open(
		cPath,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])),
		C.size_t(len(errorBuffer)),
	)
	if bridge == nil {
		return nativeContext{}, InterfaceInfo{}, fmt.Errorf("pkcs11: load %q: %s", path, trimPadded(errorBuffer))
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			C.p11x_close(bridge)
		}
	}()

	var cName *C.char
	if config.InterfaceName != "" {
		cName = C.CString(config.InterfaceName)
		defer C.free(unsafe.Pointer(cName))
	}

	var last error
	for _, version := range config.Versions {
		result := uint(C.p11x_select_interface(
			bridge,
			cName,
			C.CK_BYTE(version.Major),
			C.CK_BYTE(version.Minor),
			C.CK_FLAGS(config.InterfaceFlags),
		))
		if result == CKR_OK {
			selected := cgoSelectedInterface(bridge)
			closeOnError = false
			return nativeContext{bridge: bridge}, selected, nil
		}
		last = Error(result)
	}

	if config.AllowLegacy {
		result := uint(C.p11x_select_legacy(bridge))
		if result == CKR_OK {
			selected := cgoSelectedInterface(bridge)
			closeOnError = false
			return nativeContext{bridge: bridge}, selected, nil
		}
		last = Error(result)
	}

	if last == nil {
		last = Error(CKR_FUNCTION_NOT_SUPPORTED)
	}
	return nativeContext{}, InterfaceInfo{}, fmt.Errorf("pkcs11: no compatible interface in %q: %w", path, last)
}

func cgoSelectedInterface(bridge *C.p11x_ctx) InterfaceInfo {
	name := ""
	if value := C.p11x_interface_name(bridge); value != nil {
		name = C.GoString(value)
	}
	return InterfaceInfo{
		Name: name,
		Version: Version{
			Major: uint8(C.p11x_version_major(bridge)),
			Minor: uint8(C.p11x_version_minor(bridge)),
		},
		Flags: uint(C.p11x_interface_flags(bridge)),
	}
}

func (n nativeContext) valid() bool { return n.bridge != nil }

func (n *nativeContext) close() error {
	if n == nil || n.bridge == nil {
		return nil
	}
	C.p11x_close(n.bridge)
	n.bridge = nil
	return nil
}

func (n nativeContext) call(id functionID, arguments ...uintptr) uint {
	if n.bridge == nil {
		return CKR_FUNCTION_NOT_SUPPORTED
	}
	var values [functionMaximumArguments]C.uintptr_t
	for index, value := range arguments {
		if index >= len(values) {
			return CKR_ARGUMENTS_BAD
		}
		values[index] = C.uintptr_t(value)
	}
	return uint(C.p11x_dispatch(
		n.bridge,
		C.uint16_t(id),
		C.size_t(len(arguments)),
		values[0], values[1], values[2], values[3], values[4],
		values[5], values[6], values[7], values[8], values[9],
	))
}

// NativeAvailable reports whether this build includes a native PKCS #11
// transport. Every cgo-enabled target supported by the C compiler uses the
// generated bridge.
func NativeAvailable() bool { return true }
