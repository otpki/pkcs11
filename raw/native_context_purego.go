//go:build (!cgo || pkcs11_purego) && (linux || darwin || windows) && (amd64 || arm64)

package raw

import "fmt"

const activeNativeBackend = NativeBackendPureGo

type nativeContext struct {
	library nativeLibrary
	abi     NativeABI
	table   uintptr
	calls   [functionCount]uintptr
}

func openNativeContext(path string, config OpenConfig, abi NativeABI) (nativeContext, InterfaceInfo, error) {
	library, err := openNativeLibrary(path)
	if err != nil {
		return nativeContext{}, InterfaceInfo{}, fmt.Errorf("pkcs11: load %q: %w", path, err)
	}

	context := nativeContext{library: library, abi: abi}
	getInterface, _ := lookupNativeSymbol(library, "C_GetInterface")
	getFunctionList, _ := lookupNativeSymbol(library, "C_GetFunctionList")
	if getInterface == 0 && getFunctionList == 0 {
		_ = closeNativeLibrary(library)
		return nativeContext{}, InterfaceInfo{}, fmt.Errorf(
			"pkcs11: load %q: module exports neither C_GetInterface nor C_GetFunctionList",
			path,
		)
	}

	var last error
	if getInterface != 0 {
		for _, version := range config.Versions {
			selected, selectErr := context.selectInterface(
				abi,
				getInterface,
				config.InterfaceName,
				version,
				config.InterfaceFlags,
			)
			if selectErr == nil {
				return context, selected, nil
			}
			last = selectErr
		}
	}

	if config.AllowLegacy && getFunctionList != 0 {
		selected, selectErr := context.selectLegacy(abi, getFunctionList)
		if selectErr == nil {
			return context, selected, nil
		}
		last = selectErr
	}

	_ = context.close()
	if last == nil {
		last = Error(CKR_FUNCTION_NOT_SUPPORTED)
	}
	return nativeContext{}, InterfaceInfo{}, fmt.Errorf("pkcs11: no compatible interface in %q: %w", path, last)
}

func (n *nativeContext) selectInterface(abi NativeABI, entry uintptr, name string, version Version, flags uint) (InterfaceInfo, error) {
	arena := &nativeArena{}
	defer arena.close()

	var namePointer uintptr
	if name != "" {
		pointer, _, err := arena.copy(append([]byte(name), 0))
		if err != nil {
			return InterfaceInfo{}, err
		}
		namePointer = pointer
	}

	versionPointer, versionBytes, err := arena.alloc(2)
	if err != nil {
		return InterfaceInfo{}, err
	}
	versionBytes[0] = version.Major
	versionBytes[1] = version.Minor

	interfacePointerPointer, interfacePointerBytes, err := arena.alloc(abi.PointerSize)
	if err != nil {
		return InterfaceInfo{}, err
	}

	result := abi.ulongResult(callNative(
		entry,
		namePointer,
		versionPointer,
		interfacePointerPointer,
		abi.ulongArgument(flags),
	))
	if err := rv(result); err != nil {
		return InterfaceInfo{}, err
	}

	interfacePointer := abi.getPointer(interfacePointerBytes, 0)
	if interfacePointer == 0 {
		return InterfaceInfo{}, fmt.Errorf("pkcs11: C_GetInterface returned a nil interface")
	}
	layout := interfaceStructLayout(abi)
	bytes := nativeBytes(interfacePointer, layout.size)
	table := abi.getPointer(bytes, layout.functionList)
	if table == 0 {
		return InterfaceInfo{}, fmt.Errorf("pkcs11: C_GetInterface returned a nil function table")
	}

	versionValue := nativeBytes(table, 2)
	selected := InterfaceInfo{
		Name:    nativeCString(abi.getPointer(bytes, layout.name)),
		Version: Version{Major: versionValue[0], Minor: versionValue[1]},
		Flags:   abi.getULong(bytes, layout.flags),
	}
	if err := n.installFunctionTable(abi, table, selected); err != nil {
		return InterfaceInfo{}, err
	}
	return selected, nil
}

func (n *nativeContext) selectLegacy(abi NativeABI, entry uintptr) (InterfaceInfo, error) {
	arena := &nativeArena{}
	defer arena.close()

	pointer, bytes, err := arena.alloc(abi.PointerSize)
	if err != nil {
		return InterfaceInfo{}, err
	}
	result := abi.ulongResult(callNative(entry, pointer))
	if err := rv(result); err != nil {
		return InterfaceInfo{}, err
	}

	table := abi.getPointer(bytes, 0)
	if table == 0 {
		return InterfaceInfo{}, fmt.Errorf("pkcs11: C_GetFunctionList returned a nil function table")
	}
	versionBytes := nativeBytes(table, 2)
	selected := InterfaceInfo{
		Name:    "PKCS 11",
		Version: Version{Major: versionBytes[0], Minor: versionBytes[1]},
	}
	if err := n.installFunctionTable(abi, table, selected); err != nil {
		return InterfaceInfo{}, err
	}
	return selected, nil
}

func (n *nativeContext) installFunctionTable(abi NativeABI, table uintptr, selected InterfaceInfo) error {
	if table == 0 {
		return fmt.Errorf("pkcs11: nil function table")
	}
	firstPointer := functionTableFirstPointerOffset(abi)
	var calls [functionCount]uintptr
	for id := functionID(0); id < functionCount; id++ {
		metadata := functionTableMetadata[id]
		if !selected.Version.AtLeast(metadata.minimum) {
			continue
		}
		offset := firstPointer + int(id)*abi.PointerSize
		calls[id] = abi.pointerAt(table + uintptr(offset))
	}
	n.table = table
	n.calls = calls
	return nil
}

func (n nativeContext) valid() bool {
	return n.library != 0 && n.table != 0
}

func (n *nativeContext) close() error {
	if n == nil || n.library == 0 {
		return nil
	}
	err := closeNativeLibrary(n.library)
	n.library = 0
	n.table = 0
	n.calls = [functionCount]uintptr{}
	return err
}

func (n nativeContext) call(id functionID, arguments ...uintptr) uint {
	if id >= functionCount {
		return CKR_FUNCTION_NOT_SUPPORTED
	}
	function := n.calls[id]
	if function == 0 {
		return CKR_FUNCTION_NOT_SUPPORTED
	}
	return n.abi.ulongResult(callNative(function, arguments...))
}

// NativeAvailable reports whether this build includes the PureGo native ABI
// transport for its OS and architecture.
func NativeAvailable() bool { return true }
