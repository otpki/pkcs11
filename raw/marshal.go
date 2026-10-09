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

	result.syncBack = metadata.syncBack
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

// parameterMetadata carries an optional callback that copies provider-written
// fields (generated IVs, message tags) back into the caller's parameter value
// after the native call completes and before the arena is released.
type parameterMetadata struct {
	syncBack func()
}

func (m parameterMetadata) sync() {
	if m.syncBack != nil {
		m.syncBack()
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
		var target uintptr
		if relocation.Layout != nil {
			target, _, err = marshalLayout(arena, *relocation.Layout)
		} else {
			target, _, err = arena.copy(relocation.Data)
		}
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
	case ChaCha20Params:
		counterBits := value.BlockCounterBits
		if counterBits == 0 {
			counterBits = uint(len(value.BlockCounter)) * 8
		}
		nonceBits := value.NonceBits
		if nonceBits == 0 {
			nonceBits = uint(len(value.Nonce)) * 8
		}
		builder := NewNativeStructBuilder(abi)
		builder.AddPointer(value.BlockCounter)
		builder.AddULong(counterBits)
		builder.AddPointer(value.Nonce)
		builder.AddULong(nonceBits)
		return build(builder)
	case *ChaCha20Params:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case ChaCha20Poly1305Params:
		builder := NewNativeStructBuilder(abi)
		builder.AddPointer(value.Nonce)
		// ulNonceLen counts bytes despite spec prose claiming bits; NSS and
		// kryoptic both read byte counts, and unlike ulNonceBits the field
		// name carries the Len suffix.
		builder.AddULong(uint(len(value.Nonce)))
		builder.AddPointer(value.AAD)
		builder.AddULong(uint(len(value.AAD)))
		return build(builder)
	case *ChaCha20Poly1305Params:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case ChaCha20Poly1305MsgParams:
		return marshalChaCha20Poly1305MsgParameter(arena, value.Nonce, value.Tag, nil)
	case *ChaCha20Poly1305MsgParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalChaCha20Poly1305MsgParameter(arena, value.Nonce, value.Tag, value)
	case GCMMessageParams:
		return marshalGCMMessageParameter(arena, value, nil)
	case *GCMMessageParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalGCMMessageParameter(arena, *value, value)
	case HKDFParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddBool(value.Extract)
		builder.AddBool(value.Expand)
		builder.AddULong(value.PRFHashMechanism)
		builder.AddULong(value.SaltType)
		builder.AddPointer(value.Salt)
		builder.AddULong(uint(len(value.Salt)))
		builder.AddULong(uint(value.SaltKey))
		builder.AddPointer(value.Info)
		builder.AddULong(uint(len(value.Info)))
		return build(builder)
	case *HKDFParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case IKEPRFDeriveParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFMechanism)
		builder.AddBool(value.DataAsKey)
		builder.AddBool(value.Rekey)
		builder.AddPointer(value.Ni)
		builder.AddULong(uint(len(value.Ni)))
		builder.AddPointer(value.Nr)
		builder.AddULong(uint(len(value.Nr)))
		builder.AddULong(uint(value.NewKey))
		return build(builder)
	case *IKEPRFDeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case IKE1PRFDerivParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFMechanism)
		builder.AddBool(value.HasPrevKey)
		builder.AddULong(uint(value.KeyGxy))
		builder.AddULong(uint(value.PrevKey))
		builder.AddPointer(value.CKYi)
		builder.AddULong(uint(len(value.CKYi)))
		builder.AddPointer(value.CKYr)
		builder.AddULong(uint(len(value.CKYr)))
		builder.AddByte(value.KeyNumber)
		return build(builder)
	case *IKE1PRFDerivParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case IKE1ExtendedDeriveParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFMechanism)
		builder.AddBool(value.HasKeyGxy)
		builder.AddULong(uint(value.KeyGxy))
		builder.AddPointer(value.ExtraData)
		builder.AddULong(uint(len(value.ExtraData)))
		return build(builder)
	case *IKE1ExtendedDeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case IKE2PRFPlusDeriveParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFMechanism)
		builder.AddBool(value.HasSeedKey)
		builder.AddULong(uint(value.SeedKey))
		builder.AddPointer(value.SeedData)
		builder.AddULong(uint(len(value.SeedData)))
		return build(builder)
	case *IKE2PRFPlusDeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case KeyDerivationStringData:
		builder := NewNativeStructBuilder(abi)
		builder.AddPointer(value.Data)
		builder.AddULong(uint(len(value.Data)))
		return build(builder)
	case *KeyDerivationStringData:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case AESCBCEncryptDataParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddFixed(value.IV[:])
		builder.AddPointer(value.Data)
		builder.AddULong(uint(len(value.Data)))
		return build(builder)
	case *AESCBCEncryptDataParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case RSAAESKeyWrapParams:
		return marshalRSAAESKeyWrapParameter(arena, value)
	case *RSAAESKeyWrapParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalRSAAESKeyWrapParameter(arena, *value)
	case CCMParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.DataLen)
		builder.AddPointer(value.Nonce)
		builder.AddULong(uint(len(value.Nonce)))
		builder.AddPointer(value.AAD)
		builder.AddULong(uint(len(value.AAD)))
		builder.AddULong(value.MACLen)
		return build(builder)
	case *CCMParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case CCMMessageParams:
		return marshalCCMMessageParameter(arena, value, nil)
	case *CCMMessageParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalCCMMessageParameter(arena, *value, value)
	case GCMWrapParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddPointer(value.IV)
		builder.AddULong(uint(len(value.IV)))
		ivFixedBits := value.IVFixedBits
		if ivFixedBits == 0 {
			ivFixedBits = uint(len(value.IV)) * 8
		}
		builder.AddULong(ivFixedBits)
		builder.AddULong(value.IVGenerator)
		builder.AddPointer(value.AAD)
		builder.AddULong(uint(len(value.AAD)))
		builder.AddULong(value.TagBits)
		return build(builder)
	case *GCMWrapParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case CCMWrapParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.DataLen)
		builder.AddPointer(value.Nonce)
		builder.AddULong(uint(len(value.Nonce)))
		nonceFixedBits := value.NonceFixedBits
		if nonceFixedBits == 0 {
			nonceFixedBits = uint(len(value.Nonce)) * 8
		}
		builder.AddULong(nonceFixedBits)
		builder.AddULong(value.NonceGenerator)
		builder.AddPointer(value.AAD)
		builder.AddULong(uint(len(value.AAD)))
		builder.AddULong(value.MACLen)
		return build(builder)
	case *CCMWrapParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case PBKDF2Params:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.SaltSource)
		builder.AddPointer(value.Salt)
		builder.AddULong(uint(len(value.Salt)))
		builder.AddULong(value.Iterations)
		builder.AddULong(value.PRF)
		builder.AddPointer(value.PRFData)
		builder.AddULong(uint(len(value.PRFData)))
		builder.AddPointer(value.Password)
		builder.AddULong(uint(len(value.Password)))
		return build(builder)
	case *PBKDF2Params:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case OTPParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddNested(otpParamsLayout(abi, value.Params))
		builder.AddULong(uint(len(value.Params)))
		return build(builder)
	case *OTPParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case SP800108KDFParams:
		return marshalSP800108KDFParameter(arena, value.PRFType, value.DataParams, nil, value.AdditionalDerivedKeys)
	case *SP800108KDFParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalSP800108KDFParameter(arena, value.PRFType, value.DataParams, nil, value.AdditionalDerivedKeys)
	case SP800108FeedbackKDFParams:
		return marshalSP800108KDFParameter(arena, value.PRFType, value.DataParams, value.IV, value.AdditionalDerivedKeys)
	case *SP800108FeedbackKDFParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalSP800108KDFParameter(arena, value.PRFType, value.DataParams, value.IV, value.AdditionalDerivedKeys)
	case TLS12MasterKeyDeriveParams:
		return marshalTLS12MasterKeyDeriveParameter(arena, value)
	case *TLS12MasterKeyDeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalTLS12MasterKeyDeriveParameter(arena, *value)
	case TLS12ExtendedMasterKeyDeriveParams:
		return marshalTLS12ExtendedMasterKeyDeriveParameter(arena, value)
	case *TLS12ExtendedMasterKeyDeriveParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalTLS12ExtendedMasterKeyDeriveParameter(arena, *value)
	case TLS12KeyMatParams:
		return marshalTLS12KeyMatParameter(arena, value)
	case *TLS12KeyMatParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalTLS12KeyMatParameter(arena, *value)
	case TLSKDFParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFMechanism)
		builder.AddPointer(value.Label)
		builder.AddULong(uint(len(value.Label)))
		builder.AddPointer(value.ClientRandom)
		builder.AddULong(uint(len(value.ClientRandom)))
		builder.AddPointer(value.ServerRandom)
		builder.AddULong(uint(len(value.ServerRandom)))
		builder.AddPointer(value.ContextData)
		builder.AddULong(uint(len(value.ContextData)))
		return build(builder)
	case *TLSKDFParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case TLSMACParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.PRFHashMechanism)
		builder.AddULong(value.MACLength)
		builder.AddULong(value.ServerOrClient)
		return build(builder)
	case *TLSMACParams:
		if value == nil {
			return 0, 0, metadata, nil
		}
		return marshalParameterInto(arena, *value)
	case DSAParameterGenParams:
		builder := NewNativeStructBuilder(abi)
		builder.AddULong(value.Hash)
		builder.AddPointer(value.Seed)
		builder.AddULong(uint(len(value.Seed)))
		builder.AddULong(value.Index)
		return build(builder)
	case *DSAParameterGenParams:
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
		maximum := len(value.IV)
		metadata.syncBack = func() {
			original.IVBits = abi.getULong(root, layout.ivBits)
			original.TagBits = abi.getULong(root, layout.tagBits)
			length := min(abi.getULong(root, layout.ivLength), uint(maximum))
			if length == 0 || len(iv) == 0 {
				original.IV = original.IV[:0]
				return
			}
			size, err := abi.checkedLength(length)
			if err != nil {
				original.IV = original.IV[:0]
				return
			}
			if cap(original.IV) < size {
				original.IV = make([]byte, size)
			} else {
				original.IV = original.IV[:size]
			}
			copy(original.IV, iv[:size])
		}
	}
	return pointer, uint(layout.size), metadata, nil
}

type chacha20Poly1305MsgLayout struct {
	nonce, nonceLength, tag, size int
}

func nativeChaCha20Poly1305MsgLayout(abi NativeABI) chacha20Poly1305MsgLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := chacha20Poly1305MsgLayout{}
	layout.nonce = builder.addPointer()
	layout.nonceLength = builder.addULong()
	layout.tag = builder.addPointer()
	layout.size = builder.size()
	return layout
}

// marshalChaCha20Poly1305MsgParameter lays out
// CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS. ulNonceLen counts bytes despite
// spec prose claiming bits. Tag is copied in before the call for decryption
// and written back into original.Tag after encryption.
func marshalChaCha20Poly1305MsgParameter(arena *nativeArena, nonce, tag []byte, original *ChaCha20Poly1305MsgParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	layout := nativeChaCha20Poly1305MsgLayout(abi)
	pointer, root, err := arena.alloc(layout.size)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	noncePointer, _, err := arena.copy(nonce)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	tagLength := max(len(tag), 16)
	tagPointer, tagBuffer, err := arena.alloc(tagLength)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	copy(tagBuffer, tag)
	abi.putPointer(root, layout.nonce, noncePointer)
	abi.putULong(root, layout.nonceLength, uint(len(nonce)))
	abi.putPointer(root, layout.tag, tagPointer)
	metadata := parameterMetadata{}
	if original != nil {
		metadata.syncBack = func() {
			original.Tag = append(original.Tag[:0], tagBuffer...)
		}
	}
	return pointer, uint(layout.size), metadata, nil
}

type gcmMessageLayout struct {
	iv, ivLength, ivFixedBits, ivGenerator, tag, tagBits, size int
}

func nativeGCMMessageLayout(abi NativeABI) gcmMessageLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := gcmMessageLayout{}
	layout.iv = builder.addPointer()
	layout.ivLength = builder.addULong()
	layout.ivFixedBits = builder.addULong()
	layout.ivGenerator = builder.addULong()
	layout.tag = builder.addPointer()
	layout.tagBits = builder.addULong()
	layout.size = builder.size()
	return layout
}

// marshalGCMMessageParameter lays out CK_GCM_MESSAGE_PARAMS. Tag is copied in
// before the call for decryption and written back into original.Tag after
// encryption.
func marshalGCMMessageParameter(arena *nativeArena, value GCMMessageParams, original *GCMMessageParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	layout := nativeGCMMessageLayout(abi)
	pointer, root, err := arena.alloc(layout.size)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	ivPointer, _, err := arena.copy(value.IV)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	tagLength := len(value.Tag)
	if maximum := int((value.TagBits + 7) / 8); tagLength < maximum {
		tagLength = maximum
	}
	if tagLength < 16 {
		tagLength = 16
	}
	tagPointer, tagBuffer, err := arena.alloc(tagLength)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	copy(tagBuffer, value.Tag)
	ivFixedBits := value.IVFixedBits
	if ivFixedBits == 0 {
		ivFixedBits = uint(len(value.IV)) * 8
	}
	abi.putPointer(root, layout.iv, ivPointer)
	abi.putULong(root, layout.ivLength, uint(len(value.IV)))
	abi.putULong(root, layout.ivFixedBits, ivFixedBits)
	abi.putULong(root, layout.ivGenerator, value.IVGenerator)
	abi.putPointer(root, layout.tag, tagPointer)
	abi.putULong(root, layout.tagBits, value.TagBits)
	metadata := parameterMetadata{}
	if original != nil {
		metadata.syncBack = func() {
			original.Tag = append(original.Tag[:0], tagBuffer...)
		}
	}
	return pointer, uint(layout.size), metadata, nil
}

// oaepLayout builds the native layout of a CK_RSA_PKCS_OAEP_PARAMS structure.
func oaepLayout(abi NativeABI, value OAEPParams) *NativeParameterLayout {
	builder := NewNativeStructBuilder(abi)
	builder.AddULong(value.HashAlg)
	builder.AddULong(value.MGF)
	builder.AddULong(value.Source)
	builder.AddPointer(value.SourceData)
	builder.AddULong(uint(len(value.SourceData)))
	layout := builder.Layout()
	return &layout
}

// marshalRSAAESKeyWrapParameter lays out CK_RSA_AES_KEY_WRAP_PARAMS. A nil
// OAEPParams produces a NULL pOAEPParams, which asks the token for its default
// OAEP encoding.
func marshalRSAAESKeyWrapParameter(arena *nativeArena, value RSAAESKeyWrapParams) (uintptr, uint, parameterMetadata, error) {
	var metadata parameterMetadata
	abi := HostNativeABI()
	builder := NewNativeStructBuilder(abi)
	builder.AddULong(value.AESKeyBits)
	var oaep *NativeParameterLayout
	if value.OAEPParams != nil {
		oaep = oaepLayout(abi, *value.OAEPParams)
	}
	builder.AddNested(oaep)
	layout := builder.Layout()
	pointer, length, err := marshalLayout(arena, layout)
	return pointer, length, metadata, err
}

// otpParamsLayout builds the native layout of a CK_OTP_PARAM array.
func otpParamsLayout(abi NativeABI, params []OTPParam) *NativeParameterLayout {
	if len(params) == 0 {
		return nil
	}
	builder := NewNativeStructBuilder(abi)
	for _, param := range params {
		builder.AddULong(param.Type)
		builder.AddPointer(param.Value)
		builder.AddULong(uint(len(param.Value)))
	}
	layout := builder.Layout()
	return &layout
}

type ccmMessageLayout struct {
	dataLen, nonce, nonceLen, nonceFixedBits, nonceGenerator, mac, macLen, size int
}

func nativeCCMMessageLayout(abi NativeABI) ccmMessageLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := ccmMessageLayout{}
	layout.dataLen = builder.addULong()
	layout.nonce = builder.addPointer()
	layout.nonceLen = builder.addULong()
	layout.nonceFixedBits = builder.addULong()
	layout.nonceGenerator = builder.addULong()
	layout.mac = builder.addPointer()
	layout.macLen = builder.addULong()
	layout.size = builder.size()
	return layout
}

// marshalCCMMessageParameter lays out CK_CCM_MESSAGE_PARAMS, the per-message
// parameter of C_EncryptMessage and C_DecryptMessage. MAC is copied in for
// decryption and written back into original.MAC after encryption.
func marshalCCMMessageParameter(arena *nativeArena, value CCMMessageParams, original *CCMMessageParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	layout := nativeCCMMessageLayout(abi)
	pointer, root, err := arena.alloc(layout.size)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	noncePointer, _, err := arena.copy(value.Nonce)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	macLength := max(int(value.MACLen), len(value.MAC), 16)
	macPointer, macBuffer, err := arena.alloc(macLength)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	copy(macBuffer, value.MAC)
	nonceFixedBits := value.NonceFixedBits
	if nonceFixedBits == 0 {
		nonceFixedBits = uint(len(value.Nonce)) * 8
	}
	abi.putULong(root, layout.dataLen, value.DataLen)
	abi.putPointer(root, layout.nonce, noncePointer)
	abi.putULong(root, layout.nonceLen, uint(len(value.Nonce)))
	abi.putULong(root, layout.nonceFixedBits, nonceFixedBits)
	abi.putULong(root, layout.nonceGenerator, value.NonceGenerator)
	abi.putPointer(root, layout.mac, macPointer)
	abi.putULong(root, layout.macLen, value.MACLen)
	metadata := parameterMetadata{}
	if original != nil {
		metadata.syncBack = func() {
			length := uint(len(original.MAC))
			if reported := abi.getULong(root, layout.macLen); reported < length {
				length = reported
			}
			if length == 0 || uint(len(macBuffer)) < length {
				length = uint(len(macBuffer))
			}
			original.MAC = append(original.MAC[:0], macBuffer[:length]...)
		}
	}
	return pointer, uint(layout.size), metadata, nil
}

// sp800108DataParamsLayout builds the native CK_PRF_DATA_PARAM array. Each
// entry's pValue interpretation depends on its type: counter formats are
// embedded structures, byte arrays are raw data, and key handles are
// CK_OBJECT_HANDLE values.
func sp800108DataParamsLayout(abi NativeABI, params []SP800108DataParam) (*NativeParameterLayout, error) {
	if len(params) == 0 {
		return nil, nil
	}
	builder := NewNativeStructBuilder(abi)
	for index, param := range params {
		// Normalize value-form format structs so callers can supply either.
		switch v := param.Value.(type) {
		case SP800108CounterFormat:
			param.Value = &v
		case SP800108DKMLengthFormat:
			param.Value = &v
		}
		builder.AddULong(param.Type)
		switch value := param.Value.(type) {
		case *SP800108CounterFormat:
			if value == nil {
				builder.AddPointer(nil)
				builder.AddULong(0)
				continue
			}
			child := NewNativeStructBuilder(abi)
			child.AddBool(value.LittleEndian)
			child.AddULong(value.WidthInBits)
			childLayout := child.Layout()
			builder.AddNested(&childLayout)
			builder.AddULong(uint(len(childLayout.Root)))
		case *SP800108DKMLengthFormat:
			if value == nil {
				builder.AddPointer(nil)
				builder.AddULong(0)
				continue
			}
			child := NewNativeStructBuilder(abi)
			child.AddULong(value.Method)
			child.AddBool(value.LittleEndian)
			child.AddULong(value.WidthInBits)
			childLayout := child.Layout()
			builder.AddNested(&childLayout)
			builder.AddULong(uint(len(childLayout.Root)))
		case []byte:
			builder.AddPointer(value)
			builder.AddULong(uint(len(value)))
		case ObjectHandle:
			builder.AddPointer(nativeULong(uint(value)))
			builder.AddULong(uint(abi.ULongSize))
		case nil:
			builder.AddPointer(nil)
			builder.AddULong(0)
		default:
			return nil, fmt.Errorf("pkcs11: unsupported SP800-108 data parameter value %T at index %d", param.Value, index)
		}
	}
	layout := builder.Layout()
	return &layout, nil
}

// marshalSP800108KDFParameter lays out CK_SP800_108_KDF_PARAMS and
// CK_SP800_108_FEEDBACK_KDF_PARAMS; a nil iv omits the feedback fields. Each
// additional derived key allocates a native handle cell whose value is synced
// back into key.Key after the derive completes.
func marshalSP800108KDFParameter(arena *nativeArena, prfType uint, dataParams []SP800108DataParam, iv []byte, additional []SP800108DerivedKey) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	dataLayout, err := sp800108DataParamsLayout(abi, dataParams)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	var derivedLayout *NativeParameterLayout
	var handleBuffers [][]byte
	if len(additional) != 0 {
		arrayBuilder := NewNativeStructBuilder(abi)
		handleBuffers = make([][]byte, len(additional))
		for index, derived := range additional {
			if len(derived.Template) != 0 {
				attributes, err := buildNativeTemplate(abi, arena, derived.Template, false)
				if err != nil {
					return 0, 0, parameterMetadata{}, err
				}
				arrayBuilder.AddAddress(attributes.pointer())
			} else {
				arrayBuilder.AddPointer(nil)
			}
			arrayBuilder.AddULong(uint(len(derived.Template)))
			handlePointer, handleBuffer, err := arena.alloc(abi.ULongSize)
			if err != nil {
				return 0, 0, parameterMetadata{}, err
			}
			handleBuffers[index] = handleBuffer
			arrayBuilder.AddAddress(handlePointer)
		}
		layout := arrayBuilder.Layout()
		derivedLayout = &layout
	}
	builder := NewNativeStructBuilder(abi)
	builder.AddULong(prfType)
	builder.AddULong(uint(len(dataParams)))
	builder.AddNested(dataLayout)
	if iv != nil {
		builder.AddULong(uint(len(iv)))
		builder.AddPointer(iv)
	}
	builder.AddULong(uint(len(additional)))
	builder.AddNested(derivedLayout)
	layout := builder.Layout()
	pointer, length, err := marshalLayout(arena, layout)
	metadata := parameterMetadata{}
	if len(additional) != 0 {
		buffers := handleBuffers
		metadata.syncBack = func() {
			for index, derived := range additional {
				if derived.Key != nil && len(buffers[index]) == abi.ULongSize {
					*derived.Key = ObjectHandle(abi.getULong(buffers[index], 0))
				}
			}
		}
	}
	return pointer, length, metadata, err
}

// marshalVersionCell allocates the two-byte CK_VERSION output cell shared by
// the TLS master-key parameter shapes. A nil target produces a NULL field and
// no sync-back; otherwise the provider's version is copied into target.
func marshalVersionCell(arena *nativeArena, builder *NativeStructBuilder, target *Version) (buffer []byte, err error) {
	if target == nil {
		builder.AddPointer(nil)
		return nil, nil
	}
	pointer, buffer, err := arena.alloc(2)
	if err != nil {
		return nil, err
	}
	builder.AddAddress(pointer)
	return buffer, nil
}

// marshalTLS12MasterKeyDeriveParameter lays out
// CK_TLS12_MASTER_KEY_DERIVE_PARAMS. pVersion is a two-byte output cell synced
// back into value.Version when supplied.
func marshalTLS12MasterKeyDeriveParameter(arena *nativeArena, value TLS12MasterKeyDeriveParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	builder := NewNativeStructBuilder(abi)
	builder.AddPointer(value.ClientRandom)
	builder.AddULong(uint(len(value.ClientRandom)))
	builder.AddPointer(value.ServerRandom)
	builder.AddULong(uint(len(value.ServerRandom)))
	versionBuffer, err := marshalVersionCell(arena, builder, value.Version)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	builder.AddULong(value.PRFHashMechanism)
	layout := builder.Layout()
	pointer, length, err := marshalLayout(arena, layout)
	metadata := parameterMetadata{}
	if value.Version != nil {
		target := value.Version
		metadata.syncBack = func() {
			target.Major = versionBuffer[0]
			target.Minor = versionBuffer[1]
		}
	}
	return pointer, length, metadata, err
}

// marshalTLS12ExtendedMasterKeyDeriveParameter lays out
// CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS.
func marshalTLS12ExtendedMasterKeyDeriveParameter(arena *nativeArena, value TLS12ExtendedMasterKeyDeriveParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	builder := NewNativeStructBuilder(abi)
	builder.AddULong(value.PRFHashMechanism)
	builder.AddPointer(value.SessionHash)
	builder.AddULong(uint(len(value.SessionHash)))
	versionBuffer, err := marshalVersionCell(arena, builder, value.Version)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	layout := builder.Layout()
	pointer, length, err := marshalLayout(arena, layout)
	metadata := parameterMetadata{}
	if value.Version != nil {
		target := value.Version
		metadata.syncBack = func() {
			target.Major = versionBuffer[0]
			target.Minor = versionBuffer[1]
		}
	}
	return pointer, length, metadata, err
}

type tls12KeyMatOutLayout struct {
	clientMAC, serverMAC, clientKey, serverKey, ivClient, ivServer, size int
}

func nativeTLS12KeyMatOutLayout(abi NativeABI) tls12KeyMatOutLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := tls12KeyMatOutLayout{}
	layout.clientMAC = builder.addULong()
	layout.serverMAC = builder.addULong()
	layout.clientKey = builder.addULong()
	layout.serverKey = builder.addULong()
	layout.ivClient = builder.addPointer()
	layout.ivServer = builder.addPointer()
	layout.size = builder.size()
	return layout
}

// marshalTLS12KeyMatParameter lays out CK_TLS12_KEY_MAT_PARAMS. The returned
// key-material structure allocates native handle cells and IV buffers whose
// contents are synced into value.KeyMaterial after the derive completes.
func marshalTLS12KeyMatParameter(arena *nativeArena, value TLS12KeyMatParams) (uintptr, uint, parameterMetadata, error) {
	abi := HostNativeABI()
	outLayout := nativeTLS12KeyMatOutLayout(abi)
	outPointer, outRoot, err := arena.alloc(outLayout.size)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	ivLen := int((value.IVSizeBits + 7) / 8)
	var ivClient, ivServer []byte
	if ivLen > 0 {
		ivClientPointer, clientBuffer, err := arena.alloc(ivLen)
		if err != nil {
			return 0, 0, parameterMetadata{}, err
		}
		ivClient = clientBuffer
		abi.putPointer(outRoot, outLayout.ivClient, ivClientPointer)
		ivServerPointer, serverBuffer, err := arena.alloc(ivLen)
		if err != nil {
			return 0, 0, parameterMetadata{}, err
		}
		ivServer = serverBuffer
		abi.putPointer(outRoot, outLayout.ivServer, ivServerPointer)
	}
	builder := NewNativeStructBuilder(abi)
	builder.AddULong(value.MACSizeBits)
	builder.AddULong(value.KeySizeBits)
	builder.AddULong(value.IVSizeBits)
	builder.AddBool(value.IsExport)
	builder.AddPointer(value.ClientRandom)
	builder.AddULong(uint(len(value.ClientRandom)))
	builder.AddPointer(value.ServerRandom)
	builder.AddULong(uint(len(value.ServerRandom)))
	builder.AddAddress(outPointer)
	builder.AddULong(value.PRFHashMechanism)
	layout := builder.Layout()
	pointer, _, err := marshalLayout(arena, layout)
	if err != nil {
		return 0, 0, parameterMetadata{}, err
	}
	metadata := parameterMetadata{}
	if material := value.KeyMaterial; material != nil {
		metadata.syncBack = func() {
			material.ClientMACSecret = ObjectHandle(abi.getULong(outRoot, outLayout.clientMAC))
			material.ServerMACSecret = ObjectHandle(abi.getULong(outRoot, outLayout.serverMAC))
			material.ClientKey = ObjectHandle(abi.getULong(outRoot, outLayout.clientKey))
			material.ServerKey = ObjectHandle(abi.getULong(outRoot, outLayout.serverKey))
			if ivClient != nil {
				material.IVClient = append(material.IVClient[:0], ivClient...)
			}
			if ivServer != nil {
				material.IVServer = append(material.IVServer[:0], ivServer...)
			}
		}
	}
	return pointer, uint(len(layout.Root)), metadata, nil
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
