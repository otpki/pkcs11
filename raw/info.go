package raw

import "fmt"

type infoLayout struct {
	cryptoki, manufacturer, flags, description, libraryVersion, size int
}

func nativeInfoLayout(abi NativeABI) infoLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := infoLayout{}
	layout.cryptoki = builder.addVersion()
	layout.manufacturer = builder.addFixed(32)
	layout.flags = builder.addULong()
	layout.description = builder.addFixed(32)
	layout.libraryVersion = builder.addVersion()
	layout.size = builder.size()
	return layout
}

type interfaceLayout struct {
	name, functionList, flags, size int
}

func interfaceStructLayout(abi NativeABI) interfaceLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := interfaceLayout{}
	layout.name = builder.addPointer()
	layout.functionList = builder.addPointer()
	layout.flags = builder.addULong()
	layout.size = builder.size()
	return layout
}

func (c *Ctx) GetInfo() (Info, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return Info{}, err
	}
	defer unlock()
	layout := nativeInfoLayout(c.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(layout.size)
	if err != nil {
		return Info{}, err
	}
	if err := rv(c.call(functionGetInfo, pointer)); err != nil {
		return Info{}, err
	}
	return Info{
		CryptokiVersion:    Version{Major: value[layout.cryptoki], Minor: value[layout.cryptoki+1]},
		ManufacturerID:     trimPadded(value[layout.manufacturer : layout.manufacturer+32]),
		Flags:              c.abi.getULong(value, layout.flags),
		LibraryDescription: trimPadded(value[layout.description : layout.description+32]),
		LibraryVersion:     Version{Major: value[layout.libraryVersion], Minor: value[layout.libraryVersion+1]},
	}, nil
}

func functionListInfo(name string, flags uint, pointer uintptr) FunctionListInfo {
	info := FunctionListInfo{InterfaceInfo{Name: name, Flags: flags}, pointer}
	if pointer != 0 {
		version := nativeBytes(pointer, 2)
		info.Version = Version{Major: version[0], Minor: version[1]}
	}
	return info
}

// GetFunctionList calls C_GetFunctionList on the selected interface and
// returns its opaque native function-list pointer.
func (c *Ctx) GetFunctionList() (FunctionListInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return FunctionListInfo{}, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	pointer, bytes, err := arena.alloc(c.abi.PointerSize)
	if err != nil {
		return FunctionListInfo{}, err
	}
	if err := rv(c.call(functionGetFunctionList, pointer)); err != nil {
		return FunctionListInfo{}, err
	}
	return functionListInfo("PKCS 11", 0, c.abi.getPointer(bytes, 0)), nil
}

// GetInterface calls the PKCS #11 3.x C_GetInterface function. A nil version
// asks the implementation to select a compatible version for name and flags.
func (c *Ctx) GetInterface(name string, version *Version, flags uint) (FunctionListInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return FunctionListInfo{}, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	var namePointer, versionPointer uintptr
	if name != "" {
		namePointer, _, err = arena.copy(append([]byte(name), 0))
		if err != nil {
			return FunctionListInfo{}, err
		}
	}
	if version != nil {
		var versionBytes []byte
		var allocErr error
		versionPointer, versionBytes, allocErr = arena.alloc(2)
		if allocErr != nil {
			return FunctionListInfo{}, allocErr
		}
		versionBytes[0], versionBytes[1] = version.Major, version.Minor
	}
	interfacePointerPointer, interfacePointerBytes, err := arena.alloc(c.abi.PointerSize)
	if err != nil {
		return FunctionListInfo{}, err
	}
	if err := rv(c.call(functionGetInterface, namePointer, versionPointer, interfacePointerPointer, c.abi.ulongArgument(flags))); err != nil {
		return FunctionListInfo{}, err
	}
	interfacePointer := c.abi.getPointer(interfacePointerBytes, 0)
	if interfacePointer == 0 {
		return FunctionListInfo{}, Error(CKR_GENERAL_ERROR)
	}
	layout := interfaceStructLayout(c.abi)
	value := nativeBytes(interfacePointer, layout.size)
	list := c.abi.getPointer(value, layout.functionList)
	if list == 0 {
		return FunctionListInfo{}, Error(CKR_GENERAL_ERROR)
	}
	return functionListInfo(nativeCString(c.abi.getPointer(value, layout.name)), c.abi.getULong(value, layout.flags), list), nil
}

func (c *Ctx) GetInterfaceList() ([]InterfaceInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Although a module's interface inventory is normally static, use the same
	// bounded two-pass retry pattern as slot and mechanism enumeration. This
	// avoids trusting a count that changed between the sizing and fill calls.
	for range 4 {
		arena := &nativeArena{}
		countPointer, countBytes, err := arena.alloc(c.abi.ULongSize)
		if err != nil {
			return nil, err
		}
		value := c.call(functionGetInterfaceList, 0, countPointer)
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		count := c.abi.getULong(countBytes, 0)
		if count == 0 {
			arena.close()
			return nil, nil
		}
		layout := interfaceStructLayout(c.abi)
		total, err := checkedProduct(count, uint(layout.size))
		if err != nil {
			arena.close()
			return nil, err
		}
		interfacesPointer, interfaces, err := nativeAlloc(arena, total)
		if err != nil {
			arena.close()
			return nil, err
		}
		c.abi.putULong(countBytes, 0, count)
		value = c.call(functionGetInterfaceList, interfacesPointer, countPointer)
		returned := c.abi.getULong(countBytes, 0)
		if value == CKR_BUFFER_TOO_SMALL {
			arena.close()
			continue
		}
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		if returned > count {
			arena.close()
			return nil, fmt.Errorf("pkcs11: module returned %d interfaces for a %d-interface buffer", returned, count)
		}
		result := make([]InterfaceInfo, 0, returned)
		for index := range returned {
			offset := int(index) * layout.size
			entry := interfaces[offset : offset+layout.size]
			list := c.abi.getPointer(entry, layout.functionList)
			info := functionListInfo(nativeCString(c.abi.getPointer(entry, layout.name)), c.abi.getULong(entry, layout.flags), list)
			result = append(result, info.InterfaceInfo)
		}
		arena.close()
		return result, nil
	}
	return nil, Error(CKR_BUFFER_TOO_SMALL)
}

func (c *Ctx) GetSlotList(tokenPresent bool) ([]SlotID, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	present := uintptr(0)
	if tokenPresent {
		present = 1
	}
	for range 4 {
		arena := &nativeArena{}
		countPointer, countBytes, err := arena.alloc(c.abi.ULongSize)
		if err != nil {
			return nil, err
		}
		value := c.call(functionGetSlotList, present, 0, countPointer)
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		count := c.abi.getULong(countBytes, 0)
		if count == 0 {
			arena.close()
			return nil, nil
		}
		total, err := checkedProduct(count, uint(c.abi.ULongSize))
		if err != nil {
			arena.close()
			return nil, err
		}
		listPointer, list, err := nativeAlloc(arena, total)
		if err != nil {
			arena.close()
			return nil, err
		}
		c.abi.putULong(countBytes, 0, count)
		value = c.call(functionGetSlotList, present, listPointer, countPointer)
		returned := c.abi.getULong(countBytes, 0)
		if value == CKR_BUFFER_TOO_SMALL {
			arena.close()
			continue
		}
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		if returned > count {
			arena.close()
			return nil, fmt.Errorf("pkcs11: module returned %d slots for a %d-slot buffer", returned, count)
		}
		result := make([]SlotID, returned)
		for index := range result {
			result[index] = SlotID(c.abi.getULong(list, index*c.abi.ULongSize))
		}
		arena.close()
		return result, nil
	}
	return nil, Error(CKR_BUFFER_TOO_SMALL)
}

type slotInfoLayout struct {
	description, manufacturer, flags, hardware, firmware, size int
}

func nativeSlotInfoLayout(abi NativeABI) slotInfoLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := slotInfoLayout{}
	layout.description = builder.addFixed(64)
	layout.manufacturer = builder.addFixed(32)
	layout.flags = builder.addULong()
	layout.hardware = builder.addVersion()
	layout.firmware = builder.addVersion()
	layout.size = builder.size()
	return layout
}

func (c *Ctx) GetSlotInfo(slot SlotID) (SlotInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return SlotInfo{}, err
	}
	defer unlock()
	layout := nativeSlotInfoLayout(c.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(layout.size)
	if err != nil {
		return SlotInfo{}, err
	}
	if err := rv(c.call(functionGetSlotInfo, c.abi.ulongArgument(uint(slot)), pointer)); err != nil {
		return SlotInfo{}, err
	}
	return SlotInfo{
		SlotDescription: trimPadded(value[layout.description : layout.description+64]),
		ManufacturerID:  trimPadded(value[layout.manufacturer : layout.manufacturer+32]),
		Flags:           c.abi.getULong(value, layout.flags),
		HardwareVersion: Version{Major: value[layout.hardware], Minor: value[layout.hardware+1]},
		FirmwareVersion: Version{Major: value[layout.firmware], Minor: value[layout.firmware+1]},
	}, nil
}

type tokenInfoLayout struct {
	label, manufacturer, model, serial, flags int
	ulongs                                    [10]int
	hardware, firmware, utc, size             int
}

func nativeTokenInfoLayout(abi NativeABI) tokenInfoLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := tokenInfoLayout{}
	layout.label = builder.addFixed(32)
	layout.manufacturer = builder.addFixed(32)
	layout.model = builder.addFixed(16)
	layout.serial = builder.addFixed(16)
	layout.flags = builder.addULong()
	for index := range layout.ulongs {
		layout.ulongs[index] = builder.addULong()
	}
	layout.hardware = builder.addVersion()
	layout.firmware = builder.addVersion()
	layout.utc = builder.addFixed(16)
	layout.size = builder.size()
	return layout
}

func (c *Ctx) GetTokenInfo(slot SlotID) (TokenInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return TokenInfo{}, err
	}
	defer unlock()
	layout := nativeTokenInfoLayout(c.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(layout.size)
	if err != nil {
		return TokenInfo{}, err
	}
	if err := rv(c.call(functionGetTokenInfo, c.abi.ulongArgument(uint(slot)), pointer)); err != nil {
		return TokenInfo{}, err
	}
	values := [10]uint{}
	for index, offset := range layout.ulongs {
		values[index] = c.abi.getULong(value, offset)
	}
	return TokenInfo{
		Label:              trimPadded(value[layout.label : layout.label+32]),
		ManufacturerID:     trimPadded(value[layout.manufacturer : layout.manufacturer+32]),
		Model:              trimPadded(value[layout.model : layout.model+16]),
		SerialNumber:       trimPadded(value[layout.serial : layout.serial+16]),
		Flags:              c.abi.getULong(value, layout.flags),
		MaxSessionCount:    values[0],
		SessionCount:       values[1],
		MaxRwSessionCount:  values[2],
		RwSessionCount:     values[3],
		MaxPinLen:          values[4],
		MinPinLen:          values[5],
		TotalPublicMemory:  values[6],
		FreePublicMemory:   values[7],
		TotalPrivateMemory: values[8],
		FreePrivateMemory:  values[9],
		HardwareVersion:    Version{Major: value[layout.hardware], Minor: value[layout.hardware+1]},
		FirmwareVersion:    Version{Major: value[layout.firmware], Minor: value[layout.firmware+1]},
		UTCTime:            trimPadded(value[layout.utc : layout.utc+16]),
	}, nil
}

func (c *Ctx) GetMechanismList(slot SlotID) ([]MechanismType, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	for range 4 {
		arena := &nativeArena{}
		countPointer, countBytes, err := arena.alloc(c.abi.ULongSize)
		if err != nil {
			return nil, err
		}
		value := c.call(functionGetMechanismList, c.abi.ulongArgument(uint(slot)), 0, countPointer)
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		count := c.abi.getULong(countBytes, 0)
		if count == 0 {
			arena.close()
			return nil, nil
		}
		total, err := checkedProduct(count, uint(c.abi.ULongSize))
		if err != nil {
			arena.close()
			return nil, err
		}
		listPointer, list, err := nativeAlloc(arena, total)
		if err != nil {
			arena.close()
			return nil, err
		}
		c.abi.putULong(countBytes, 0, count)
		value = c.call(functionGetMechanismList, c.abi.ulongArgument(uint(slot)), listPointer, countPointer)
		returned := c.abi.getULong(countBytes, 0)
		if value == CKR_BUFFER_TOO_SMALL {
			arena.close()
			continue
		}
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		if returned > count {
			arena.close()
			return nil, fmt.Errorf("pkcs11: module returned %d mechanisms for a %d-mechanism buffer", returned, count)
		}
		result := make([]MechanismType, returned)
		for index := range result {
			result[index] = MechanismType(c.abi.getULong(list, index*c.abi.ULongSize))
		}
		arena.close()
		return result, nil
	}
	return nil, Error(CKR_BUFFER_TOO_SMALL)
}

type mechanismInfoLayout struct{ min, max, flags, size int }

func nativeMechanismInfoLayout(abi NativeABI) mechanismInfoLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := mechanismInfoLayout{min: builder.addULong(), max: builder.addULong(), flags: builder.addULong()}
	layout.size = builder.size()
	return layout
}

func (c *Ctx) GetMechanismInfo(slot SlotID, mechanism MechanismType) (MechanismInfo, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return MechanismInfo{}, err
	}
	defer unlock()
	layout := nativeMechanismInfoLayout(c.abi)
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(layout.size)
	if err != nil {
		return MechanismInfo{}, err
	}
	if err := rv(c.call(functionGetMechanismInfo, c.abi.ulongArgument(uint(slot)), c.abi.ulongArgument(uint(mechanism)), pointer)); err != nil {
		return MechanismInfo{}, err
	}
	return MechanismInfo{MinKeySize: c.abi.getULong(value, layout.min), MaxKeySize: c.abi.getULong(value, layout.max), Flags: c.abi.getULong(value, layout.flags)}, nil
}

func (c *Ctx) InitToken(slot SlotID, pin []byte, label string) error {
	if len(label) > 32 {
		return fmt.Errorf("pkcs11: token label is %d bytes; maximum is 32", len(label))
	}
	labelBytes := make([]byte, 32)
	for index := range labelBytes {
		labelBytes[index] = ' '
	}
	copy(labelBytes, label)
	arena := &nativeArena{}
	defer arena.close()
	pinPointer, err := nativeCopySecret(arena, pin)
	if err != nil {
		return err
	}
	labelPointer, err := nativeCopy(arena, labelBytes)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionInitToken, c.abi.ulongArgument(uint(slot)), pinPointer, c.abi.ulongArgument(uint(len(pin))), labelPointer))
}
