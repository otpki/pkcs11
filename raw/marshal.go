package raw

import (
	"errors"
	"fmt"
)

// This file owns the boundary between Go values and native PKCS #11 memory.
// cgo and PureGo build the same ABI layouts, using C allocations or pinned Go
// storage respectively. Mechanism and template memory must remain alive for the
// full native operation, including multipart calls.

// nativeULong encodes value exactly as one host-native CK_ULONG. It is an ABI
// representation, not a portable serialization format.
func nativeULong(value uint) []byte {
	abi := HostNativeABI()
	out := make([]byte, abi.ULongSize)
	abi.putULong(out, 0, value)
	return out
}

// nativeULongs encodes values as a contiguous host-native CK_ULONG array.
func nativeULongs(values []uint) []byte {
	if len(values) == 0 {
		return nil
	}
	abi := HostNativeABI()
	size, err := checkedProduct(uint(len(values)), uint(abi.ULongSize))
	if err != nil {
		panic(fmt.Sprintf("pkcs11: marshal %d CK_ULONGs: %v", len(values), err))
	}
	out := make([]byte, size)
	for index, value := range values {
		abi.putULong(out, index*abi.ULongSize, value)
	}
	return out
}

// ulongFromBytes decodes exactly one host-native CK_ULONG.
func ulongFromBytes(value []byte) (uint, bool) {
	abi := HostNativeABI()
	if len(value) != abi.ULongSize {
		return 0, false
	}
	return abi.getULong(value, 0), true
}

type attributeLayout struct {
	typ, value, length, size int
}

func nativeAttributeLayout(abi NativeABI) attributeLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := attributeLayout{}
	layout.typ = builder.addULong()
	layout.value = builder.addPointer()
	layout.length = builder.addULong()
	layout.size = builder.size()
	return layout
}

// nativeTemplate owns one native CK_ATTRIBUTE array and every value or
// recursively nested template reachable from it. All descendants share arena,
// so free releases the complete tree exactly once.
type nativeTemplate struct {
	abi      NativeABI
	arena    *nativeArena
	root     []byte
	count    uint
	children []*nativeTemplate
	owner    bool
}

func (t *nativeTemplate) pointer() uintptr { return nativePointer(t.root) }

func (t *nativeTemplate) free() {
	if t == nil || !t.owner {
		return
	}
	t.owner = false
	t.arena.close()
	t.root = nil
	t.children = nil
}

func newNativeTemplate(attributes []*Attribute, get bool) (*nativeTemplate, error) {
	arena := &nativeArena{}
	template, err := buildNativeTemplate(HostNativeABI(), arena, attributes, get)
	if err != nil {
		arena.close()
		return nil, err
	}
	template.owner = true
	return template, nil
}

func buildNativeTemplate(abi NativeABI, arena *nativeArena, attributes []*Attribute, get bool) (*nativeTemplate, error) {
	layout := nativeAttributeLayout(abi)
	template := &nativeTemplate{abi: abi, arena: arena, count: uint(len(attributes))}
	if len(attributes) == 0 {
		return template, nil
	}
	size, err := checkedProduct(uint(len(attributes)), uint(layout.size))
	if err != nil {
		return nil, fmt.Errorf("pkcs11: attribute template too large: %w", err)
	}
	_, root, err := arena.alloc(int(size))
	if err != nil {
		return nil, fmt.Errorf("pkcs11: allocate attribute template: %w", err)
	}
	template.root = root

	for index, attribute := range attributes {
		if attribute == nil {
			return nil, fmt.Errorf("pkcs11: nil attribute at index %d", index)
		}
		offset := index * layout.size
		abi.putULong(root, offset+layout.typ, attribute.Type)
		if attribute.Children != nil {
			child, err := buildNativeTemplate(abi, arena, attribute.Children, get)
			if err != nil {
				return nil, err
			}
			template.children = append(template.children, child)
			abi.putPointer(root, offset+layout.value, child.pointer())
			abi.putULong(root, offset+layout.length, child.count*uint(layout.size))
			continue
		}
		if get || len(attribute.Value) == 0 {
			continue
		}
		pointer, _, err := arena.copy(attribute.Value)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: allocate attribute value: %w", err)
		}
		abi.putPointer(root, offset+layout.value, pointer)
		abi.putULong(root, offset+layout.length, uint(len(attribute.Value)))
	}
	return template, nil
}

// marshalTemplate creates an input CK_ATTRIBUTE array.
func marshalTemplate(attributes []*Attribute) (*nativeTemplate, error) {
	return newNativeTemplate(attributes, false)
}

// newGetTemplate creates the first-pass CK_ATTRIBUTE array for
// C_GetAttributeValue. Ordinary value pointers are nil so the module can return
// required lengths; nested template shapes are supplied recursively.
func newGetTemplate(attributes []*Attribute) (*nativeTemplate, error) {
	return newNativeTemplate(attributes, true)
}

func (abi NativeABI) unavailableInformation() uint {
	if abi.ULongSize == 4 {
		return uint(^uint32(0))
	}
	return ^uint(0)
}

// allocateGetValues allocates the exact buffers requested by the first
// C_GetAttributeValue pass and patches their stable addresses into the
// template.
func (t *nativeTemplate) allocateGetValues(attributes []*Attribute) error {
	if t == nil {
		return errors.New("pkcs11: nil attribute template")
	}
	layout := nativeAttributeLayout(t.abi)
	childIndex := 0
	for index, attribute := range attributes {
		offset := index * layout.size
		if attribute.Children != nil {
			child := t.children[childIndex]
			childIndex++
			if err := child.allocateGetValues(attribute.Children); err != nil {
				return err
			}
			t.abi.putPointer(t.root, offset+layout.value, child.pointer())
			t.abi.putULong(t.root, offset+layout.length, child.count*uint(layout.size))
			continue
		}
		length := t.abi.getULong(t.root, offset+layout.length)
		if length == 0 || length == t.abi.unavailableInformation() {
			continue
		}
		size, err := t.abi.checkedLength(length)
		if err != nil {
			return err
		}
		pointer, _, err := t.arena.alloc(size)
		if err != nil {
			return fmt.Errorf("pkcs11: allocate %d-byte attribute value: %w", length, err)
		}
		t.abi.putPointer(t.root, offset+layout.value, pointer)
	}
	return nil
}

// copyGetValues copies a completed native template into independent Go values.
func (t *nativeTemplate) copyGetValues(attributes []*Attribute) []*Attribute {
	result := make([]*Attribute, len(attributes))
	layout := nativeAttributeLayout(t.abi)
	childIndex := 0
	for index, requested := range attributes {
		attribute := &Attribute{Type: requested.Type}
		offset := index * layout.size
		if requested.Children != nil {
			attribute.Children = t.children[childIndex].copyGetValues(requested.Children)
			childIndex++
		} else {
			length := t.abi.getULong(t.root, offset+layout.length)
			pointer := t.abi.getPointer(t.root, offset+layout.value)
			if length != t.abi.unavailableInformation() && pointer != 0 {
				if size, err := t.abi.checkedLength(length); err == nil {
					attribute.Value = copyNativeBytes(pointer, uint(size))
				}
			}
		}
		result[index] = attribute
	}
	return result
}

type mechanismLayout struct {
	mechanism, parameter, length, size int
}

func nativeMechanismLayout(abi NativeABI) mechanismLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := mechanismLayout{}
	layout.mechanism = builder.addULong()
	layout.parameter = builder.addPointer()
	layout.length = builder.addULong()
	layout.size = builder.size()
	return layout
}

// nativeMechanism owns a native CK_MECHANISM and every buffer referenced by
// pParameter. syncBack copies provider-written output fields before release.
type nativeMechanism struct {
	abi      NativeABI
	arena    *nativeArena
	root     []byte
	syncBack func()
	freed    bool
}

func (m *nativeMechanism) pointer() uintptr { return nativePointer(m.root) }

func (m *nativeMechanism) free() {
	if m == nil || m.freed {
		return
	}
	m.freed = true
	if m.syncBack != nil {
		m.syncBack()
		m.syncBack = nil
	}
	m.arena.close()
	m.root = nil
}

func marshalMechanism(mechanism *Mechanism) (*nativeMechanism, error) {
	if mechanism == nil {
		return nil, errors.New("pkcs11: nil mechanism")
	}
	abi := HostNativeABI()
	arena := &nativeArena{}
	layout := nativeMechanismLayout(abi)
	_, root, err := arena.alloc(layout.size)
	if err != nil {
		arena.close()
		return nil, err
	}
	result := &nativeMechanism{abi: abi, arena: arena, root: root}
	abi.putULong(root, layout.mechanism, mechanism.Mechanism)

	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, mechanism.Parameter)
	if err != nil {
		result.free()
		return nil, err
	}
	abi.putPointer(root, layout.parameter, parameterPointer)
	abi.putULong(root, layout.length, parameterLength)

	if params, ok := mechanism.Parameter.(*GCMParams); ok && params != nil && metadata.gcm != nil {
		gcm := metadata.gcm
		maximum := gcm.maximumIV
		result.syncBack = func() {
			params.IVBits = abi.getULong(gcm.root, gcm.layout.ivBits)
			params.TagBits = abi.getULong(gcm.root, gcm.layout.tagBits)
			length := min(abi.getULong(gcm.root, gcm.layout.ivLength), uint(maximum))
			if length == 0 || len(gcm.iv) == 0 {
				params.IV = params.IV[:0]
				return
			}
			size, err := abi.checkedLength(length)
			if err != nil {
				params.IV = params.IV[:0]
				return
			}
			if cap(params.IV) < size {
				params.IV = make([]byte, size)
			} else {
				params.IV = params.IV[:size]
			}
			copy(params.IV, gcm.iv[:size])
		}
	}
	return result, nil
}

func onlyMechanism(mechanisms []*Mechanism) (*nativeMechanism, error) {
	if len(mechanisms) != 1 {
		return nil, fmt.Errorf("pkcs11: exactly one mechanism is required, got %d", len(mechanisms))
	}
	return marshalMechanism(mechanisms[0])
}

type gcmParameterLayout struct {
	iv, ivLength, ivBits, aad, aadLength, tagBits, size int
}

func nativeGCMParameterLayout(abi NativeABI) gcmParameterLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := gcmParameterLayout{}
	layout.iv = builder.addPointer()
	layout.ivLength = builder.addULong()
	layout.ivBits = builder.addULong()
	layout.aad = builder.addPointer()
	layout.aadLength = builder.addULong()
	layout.tagBits = builder.addULong()
	layout.size = builder.size()
	return layout
}

type parameterMetadata struct {
	gcm *struct {
		root      []byte
		iv        []byte
		layout    gcmParameterLayout
		maximumIV int
	}
}

func marshalLayout(arena *nativeArena, layout NativeParameterLayout) (uintptr, uint, error) {
	if len(layout.Root) == 0 {
		return 0, 0, nil
	}
	abi := HostNativeABI()
	pointer, root, err := arena.copy(layout.Root)
	if err != nil {
		return 0, 0, err
	}
	for _, relocation := range layout.Pointers {
		if relocation.Offset < 0 || relocation.Offset+abi.PointerSize > len(root) {
			return 0, 0, fmt.Errorf("pkcs11: native parameter pointer offset %d outside %d-byte root", relocation.Offset, len(root))
		}
		target, _, err := arena.copy(relocation.Data)
		if err != nil {
			return 0, 0, err
		}
		abi.putPointer(root, relocation.Offset, target)
	}
	return pointer, uint(len(root)), nil
}

func marshalParameterInto(arena *nativeArena, parameter any) (uintptr, uint, parameterMetadata, error) {
	var metadata parameterMetadata
	abi := HostNativeABI()
	copyValue := func(value []byte) (uintptr, uint, parameterMetadata, error) {
		pointer, _, err := arena.copy(value)
		return pointer, uint(len(value)), metadata, err
	}
	build := func(builder *NativeStructBuilder) (uintptr, uint, parameterMetadata, error) {
		layout := builder.Layout()
		pointer, length, err := marshalLayout(arena, layout)
		return pointer, length, metadata, err
	}

	switch value := parameter.(type) {
	case nil:
		return 0, 0, metadata, nil
	case UnsafeParameter:
		return uintptr(value.Pointer), value.Length, metadata, nil
	case *UnsafeParameter:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return uintptr(value.Pointer), value.Length, metadata, nil
	case []byte:
		return copyValue(value)
	case string:
		return copyValue([]byte(value))
	case uint:
		return copyValue(nativeULong(value))
	case NativeParameterMarshaler:
		layout, err := value.MarshalPKCS11Native(abi)
		if err != nil {
			return 0, 0, metadata, err
		}
		pointer, length, err := marshalLayout(arena, layout)
		return pointer, length, metadata, err
	case ParameterMarshaler:
		data, err := value.MarshalPKCS11Parameter()
		if err != nil {
			return 0, 0, metadata, err
		}
		return copyValue(data)
	case PSSParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.HashAlg)
		builder.AddULong(value.MGF)
		builder.AddULong(value.SaltLen)
		return build(builder)
	case *PSSParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case OAEPParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.HashAlg)
		builder.AddULong(value.MGF)
		builder.AddULong(value.Source)
		builder.AddPointer(value.SourceData)
		builder.AddULong(uint(len(value.SourceData)))
		return build(builder)
	case *OAEPParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case AESCTRParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.CounterBits)
		builder.AddFixed(value.Counter[:])
		return build(builder)
	case *AESCTRParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case GCMParams:
		return marshalGCMParameter(arena, value, nil)
	case *GCMParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalGCMParameter(arena, *value, value)
	case ECDH1DeriveParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.KDF)
		builder.AddULong(uint(len(value.SharedData)))
		builder.AddPointer(value.SharedData)
		builder.AddULong(uint(len(value.PublicData)))
		builder.AddPointer(value.PublicData)
		return build(builder)
	case *ECDH1DeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case EdDSAParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddBool(value.Prehash)
		builder.AddULong(uint(len(value.Context)))
		builder.AddPointer(value.Context)
		return build(builder)
	case *EdDSAParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case SignAdditionalContext:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(uint(value.Hedge))
		builder.AddPointer(value.Context)
		builder.AddULong(uint(len(value.Context)))
		return build(builder)
	case *SignAdditionalContext:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case HashSignAdditionalContext:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(uint(value.Hedge))
		builder.AddPointer(value.Context)
		builder.AddULong(uint(len(value.Context)))
		builder.AddULong(value.Hash)
		return build(builder)
	case *HashSignAdditionalContext:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	default:
		return 0, 0, metadata, fmt.Errorf("pkcs11: unsupported mechanism parameter %T", parameter)
	}
}

func marshalGCMParameter(arena *nativeArena, value GCMParams, original *GCMParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	layout := nativeGCMParameterLayout(abi)
	pointer, root, err := arena.alloc(layout.size)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	ivPointer, iv, err := arena.copy(value.IV)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	aadPointer, _, err := arena.copy(value.AAD)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	abi.putPointer(root, layout.iv, ivPointer)
	abi.putULong(root, layout.ivLength, uint(len(value.IV)))
	abi.putULong(root, layout.ivBits, value.IVBits)
	abi.putPointer(root, layout.aad, aadPointer)
	abi.putULong(root, layout.aadLength, uint(len(value.AAD)))
	abi.putULong(root, layout.tagBits, value.TagBits)
	metadata := parameterMetadata{}
	if original != nil {
		metadata.gcm = &struct {
			root      []byte
			iv        []byte
			layout    gcmParameterLayout
			maximumIV int
		}{root: root, iv: iv, layout: layout, maximumIV: len(value.IV)}
	}
	return pointer, uint(layout.size), metadata, nil
}

// nativeCopy allocates a short-lived native copy for one call.
func nativeCopy(arena *nativeArena, data []byte) (uintptr, error) {
	pointer, _, err := arena.copy(data)
	return pointer, err
}

// nativeCopySecret allocates a short-lived credential copy that is wiped before
// the arena releases its native storage.
func nativeCopySecret(arena *nativeArena, data []byte) (uintptr, error) {
	pointer, _, err := arena.copySecret(data)
	return pointer, err
}

// nativeAlloc allocates a zeroed native output buffer.
func nativeAlloc(arena *nativeArena, length uint) (uintptr, []byte, error) {
	size, err := HostNativeABI().checkedLength(length)
	if err != nil {
		return 0, nil, err
	}
	return arena.alloc(size)
}
