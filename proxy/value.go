package proxy

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/otpki/pkcs11/raw"
)

type valueKind uint8

const (
	valueInvalid valueKind = iota
	valueNil
	valueBool
	valueUint
	valueInt
	valueString
	valueBytes
	valueList
	valueStruct
	valueParameter
)

type fieldValue struct {
	Name  string
	Value wireValue
}

type wireValue struct {
	Kind      valueKind
	Bool      bool
	Uint      uint64
	Int       int64
	String    string
	Bytes     []byte
	Items     []wireValue
	Fields    []fieldValue
	Parameter parameterValue
}

var (
	anyType              = reflect.TypeFor[any]()
	unsafePointerType    = reflect.TypeFor[unsafe.Pointer]()
	functionListInfoType = reflect.TypeFor[raw.FunctionListInfo]()
)

func encodeWireValue(input any, registry *CodecRegistry) (wireValue, error) {
	return encodeReflectValue(reflect.ValueOf(input), registry)
}

// encodeTypedWireValue preserves the declared interface type of a Cryptoki
// argument. A value carried in an `any` parameter must use the parameter codec
// even though reflect.ValueOf exposes only its concrete dynamic type.
func encodeTypedWireValue(input any, declared reflect.Type, registry *CodecRegistry) (wireValue, error) {
	if declared == anyType || declared.Kind() == reflect.Interface {
		parameter, err := encodeParameter(input, registry)
		if err != nil {
			return wireValue{}, err
		}
		return wireValue{Kind: valueParameter, Parameter: parameter}, nil
	}
	return encodeWireValue(input, registry)
}

func encodeReflectValue(value reflect.Value, registry *CodecRegistry) (wireValue, error) {
	if !value.IsValid() {
		return wireValue{Kind: valueNil}, nil
	}
	if value.Type() == anyType || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return wireValue{Kind: valueNil}, nil
		}
		parameter, err := encodeParameter(value.Interface(), registry)
		if err != nil {
			return wireValue{}, err
		}
		return wireValue{Kind: valueParameter, Parameter: parameter}, nil
	}
	if value.Type() == unsafePointerType || value.Kind() == reflect.UnsafePointer {
		return wireValue{}, fmt.Errorf("pkcs11 proxy: unsafe pointers cannot cross the wire")
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return wireValue{Kind: valueNil}, nil
		}
		return encodeReflectValue(value.Elem(), registry)
	case reflect.Bool:
		return wireValue{Kind: valueBool, Bool: value.Bool()}, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return wireValue{Kind: valueUint, Uint: value.Uint()}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return wireValue{Kind: valueInt, Int: value.Int()}, nil
	case reflect.String:
		return wireValue{Kind: valueString, String: value.String()}, nil
	case reflect.Slice:
		if value.IsNil() {
			return wireValue{Kind: valueNil}, nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return wireValue{Kind: valueBytes, Bytes: append([]byte(nil), value.Bytes()...)}, nil
		}
		items := make([]wireValue, value.Len())
		for i := range items {
			encoded, err := encodeReflectValue(value.Index(i), registry)
			if err != nil {
				return wireValue{}, fmt.Errorf("pkcs11 proxy: encode slice element %d: %w", i, err)
			}
			items[i] = encoded
		}
		return wireValue{Kind: valueList, Items: items}, nil
	case reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, value.Len())
			for i := range data {
				data[i] = byte(value.Index(i).Uint())
			}
			return wireValue{Kind: valueBytes, Bytes: data}, nil
		}
		items := make([]wireValue, value.Len())
		for i := range items {
			encoded, err := encodeReflectValue(value.Index(i), registry)
			if err != nil {
				return wireValue{}, err
			}
			items[i] = encoded
		}
		return wireValue{Kind: valueList, Items: items}, nil
	case reflect.Struct:
		fields := make([]fieldValue, 0, value.NumField())
		for i := 0; i < value.NumField(); i++ {
			fieldType := value.Type().Field(i)
			if !fieldType.IsExported() {
				continue
			}
			field := value.Field(i)
			// A native function-list pointer is process-local and meaningless to a
			// remote caller. Preserve the interface metadata but never disclose it.
			if value.Type() == functionListInfoType && fieldType.Name == "Pointer" {
				fields = append(fields, fieldValue{Name: fieldType.Name, Value: wireValue{Kind: valueUint}})
				continue
			}
			encoded, err := encodeReflectValue(field, registry)
			if err != nil {
				return wireValue{}, fmt.Errorf("pkcs11 proxy: encode %s.%s: %w", value.Type(), fieldType.Name, err)
			}
			fields = append(fields, fieldValue{Name: fieldType.Name, Value: encoded})
		}
		return wireValue{Kind: valueStruct, Fields: fields}, nil
	default:
		return wireValue{}, fmt.Errorf("pkcs11 proxy: unsupported wire value %s", value.Type())
	}
}

func decodeWireValue(encoded wireValue, target reflect.Type, registry *CodecRegistry) (reflect.Value, error) {
	if target == nil {
		return reflect.Value{}, fmt.Errorf("pkcs11 proxy: nil target type")
	}
	if target == anyType || target.Kind() == reflect.Interface {
		if encoded.Kind == valueNil {
			return reflect.Zero(target), nil
		}
		if encoded.Kind != valueParameter {
			return reflect.Value{}, fmt.Errorf("pkcs11 proxy: expected parameter value for %s", target)
		}
		parameter, err := decodeParameter(encoded.Parameter, registry)
		if err != nil {
			return reflect.Value{}, err
		}
		if parameter == nil {
			return reflect.Zero(target), nil
		}
		value := reflect.ValueOf(parameter)
		if value.Type().AssignableTo(target) {
			return value, nil
		}
		return value, nil
	}
	if encoded.Kind == valueNil {
		switch target.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
			return reflect.Zero(target), nil
		default:
			return reflect.Value{}, fmt.Errorf("pkcs11 proxy: nil cannot decode into %s", target)
		}
	}
	if target.Kind() == reflect.Pointer {
		value, err := decodeWireValue(encoded, target.Elem(), registry)
		if err != nil {
			return reflect.Value{}, err
		}
		pointer := reflect.New(target.Elem())
		pointer.Elem().Set(value)
		return pointer, nil
	}
	result := reflect.New(target).Elem()
	switch target.Kind() {
	case reflect.Bool:
		if encoded.Kind != valueBool {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		result.SetBool(encoded.Bool)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if encoded.Kind != valueUint {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		if target.Bits() < 64 && encoded.Uint > (uint64(1)<<target.Bits())-1 {
			return reflect.Value{}, fmt.Errorf("pkcs11 proxy: %d overflows %s", encoded.Uint, target)
		}
		result.SetUint(encoded.Uint)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if encoded.Kind != valueInt {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		bits := target.Bits()
		if bits < 64 {
			min, max := -(int64(1) << (bits - 1)), (int64(1)<<(bits-1))-1
			if encoded.Int < min || encoded.Int > max {
				return reflect.Value{}, fmt.Errorf("pkcs11 proxy: %d overflows %s", encoded.Int, target)
			}
		}
		result.SetInt(encoded.Int)
	case reflect.String:
		if encoded.Kind != valueString {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		result.SetString(encoded.String)
	case reflect.Slice:
		if target.Elem().Kind() == reflect.Uint8 {
			if encoded.Kind != valueBytes {
				return reflect.Value{}, typeMismatch(encoded, target)
			}
			result.SetBytes(append([]byte(nil), encoded.Bytes...))
			break
		}
		if encoded.Kind != valueList {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		slice := reflect.MakeSlice(target, len(encoded.Items), len(encoded.Items))
		for i, item := range encoded.Items {
			value, err := decodeWireValue(item, target.Elem(), registry)
			if err != nil {
				return reflect.Value{}, fmt.Errorf("pkcs11 proxy: decode slice element %d: %w", i, err)
			}
			slice.Index(i).Set(value)
		}
		result.Set(slice)
	case reflect.Array:
		if target.Elem().Kind() == reflect.Uint8 {
			if encoded.Kind != valueBytes || len(encoded.Bytes) != target.Len() {
				return reflect.Value{}, typeMismatch(encoded, target)
			}
			for i, value := range encoded.Bytes {
				result.Index(i).SetUint(uint64(value))
			}
			break
		}
		if encoded.Kind != valueList || len(encoded.Items) != target.Len() {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		for i, item := range encoded.Items {
			value, err := decodeWireValue(item, target.Elem(), registry)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Index(i).Set(value)
		}
	case reflect.Struct:
		if encoded.Kind != valueStruct {
			return reflect.Value{}, typeMismatch(encoded, target)
		}
		fields := make(map[string]wireValue, len(encoded.Fields))
		for _, field := range encoded.Fields {
			if field.Name == "" {
				return reflect.Value{}, fmt.Errorf("pkcs11 proxy: empty struct field name")
			}
			if _, exists := fields[field.Name]; exists {
				return reflect.Value{}, fmt.Errorf("pkcs11 proxy: duplicate struct field %q", field.Name)
			}
			fields[field.Name] = field.Value
		}
		for i := 0; i < target.NumField(); i++ {
			fieldType := target.Field(i)
			if !fieldType.IsExported() {
				continue
			}
			fieldValue, exists := fields[fieldType.Name]
			if !exists {
				continue
			}
			value, err := decodeWireValue(fieldValue, fieldType.Type, registry)
			if err != nil {
				return reflect.Value{}, fmt.Errorf("pkcs11 proxy: decode %s.%s: %w", target, fieldType.Name, err)
			}
			result.Field(i).Set(value)
		}
	default:
		return reflect.Value{}, fmt.Errorf("pkcs11 proxy: unsupported decode target %s", target)
	}
	return result, nil
}

func typeMismatch(encoded wireValue, target reflect.Type) error {
	return fmt.Errorf("pkcs11 proxy: wire kind %d cannot decode into %s", encoded.Kind, target)
}

func argumentMayMutate(method string, index int, declared reflect.Type) bool {
	if declared == nil {
		return false
	}
	// Mechanism parameters carried as any may contain provider-written output
	// (for example a generated GCM IV). They are synchronized separately from
	// ordinary return values.
	if declared == anyType || declared.Kind() == reflect.Interface {
		return true
	}
	switch method {
	case "AsyncComplete":
		return index == 2 && declared.Kind() == reflect.Pointer
	case "AsyncJoin":
		return index == 3 && declared.Kind() == reflect.Slice && declared.Elem().Kind() == reflect.Uint8
	default:
		return false
	}
}

const (
	maximumWireDepth = 32
	maximumWireNodes = 1 << 20
)

// validateWireValue rejects malformed or pathologically nested values before
// reflection-based decoding. The outer frame already bounds bytes; these limits
// additionally bound recursive work and prevent duplicate struct fields from
// being interpreted differently by validators and decoders.
func validateWireValue(value wireValue) error {
	nodes := 0
	var visit func(wireValue, int) error
	visit = func(current wireValue, depth int) error {
		if depth > maximumWireDepth {
			return fmt.Errorf("pkcs11 proxy: wire value exceeds maximum depth %d", maximumWireDepth)
		}
		nodes++
		if nodes > maximumWireNodes {
			return fmt.Errorf("pkcs11 proxy: wire value exceeds maximum node count %d", maximumWireNodes)
		}
		switch current.Kind {
		case valueNil, valueBool, valueUint, valueInt, valueString, valueBytes:
			if len(current.Items) != 0 || len(current.Fields) != 0 {
				return fmt.Errorf("pkcs11 proxy: scalar wire value contains children")
			}
		case valueList:
			for _, item := range current.Items {
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
		case valueStruct:
			seen := make(map[string]struct{}, len(current.Fields))
			for _, field := range current.Fields {
				if field.Name == "" {
					return fmt.Errorf("pkcs11 proxy: empty struct field name")
				}
				if _, exists := seen[field.Name]; exists {
					return fmt.Errorf("pkcs11 proxy: duplicate struct field %q", field.Name)
				}
				seen[field.Name] = struct{}{}
				if err := visit(field.Value, depth+1); err != nil {
					return err
				}
			}
		case valueParameter:
			if current.Parameter.Kind == "" {
				return fmt.Errorf("pkcs11 proxy: empty parameter kind")
			}
		case valueInvalid:
			return fmt.Errorf("pkcs11 proxy: invalid wire value kind")
		default:
			return fmt.Errorf("pkcs11 proxy: unknown wire value kind %d", current.Kind)
		}
		return nil
	}
	return visit(value, 0)
}

func cloneWireValue(value wireValue) wireValue {
	result := value
	result.Bytes = append([]byte(nil), value.Bytes...)
	result.Parameter.Data = append([]byte(nil), value.Parameter.Data...)
	if len(value.Items) != 0 {
		result.Items = make([]wireValue, len(value.Items))
		for index := range value.Items {
			result.Items[index] = cloneWireValue(value.Items[index])
		}
	}
	if len(value.Fields) != 0 {
		result.Fields = make([]fieldValue, len(value.Fields))
		for index := range value.Fields {
			result.Fields[index] = fieldValue{Name: value.Fields[index].Name, Value: cloneWireValue(value.Fields[index].Value)}
		}
	}
	return result
}

func wipeWireValue(value *wireValue) {
	if value == nil {
		return
	}
	wipe(value.Bytes)
	wipe(value.Parameter.Data)
	for index := range value.Items {
		wipeWireValue(&value.Items[index])
	}
	for index := range value.Fields {
		wipeWireValue(&value.Fields[index].Value)
	}
	*value = wireValue{}
}

func wipeAny(value any) {
	if value == nil {
		return
	}
	wipeReflectValue(reflect.ValueOf(value), make(map[uintptr]struct{}))
}

func wipeReflectValue(value reflect.Value, seen map[uintptr]struct{}) {
	if !value.IsValid() {
		return
	}
	switch value.Kind() {
	case reflect.Interface:
		if !value.IsNil() {
			wipeReflectValue(value.Elem(), seen)
		}
	case reflect.Pointer:
		if value.IsNil() {
			return
		}
		pointer := value.Pointer()
		if pointer != 0 {
			if _, ok := seen[pointer]; ok {
				return
			}
			seen[pointer] = struct{}{}
		}
		wipeReflectValue(value.Elem(), seen)
	case reflect.Slice:
		if value.IsNil() {
			return
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			for index := 0; index < value.Len(); index++ {
				value.Index(index).SetUint(0)
			}
			return
		}
		for index := 0; index < value.Len(); index++ {
			wipeReflectValue(value.Index(index), seen)
		}
	case reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 && value.CanSet() {
			for index := 0; index < value.Len(); index++ {
				value.Index(index).SetUint(0)
			}
			return
		}
		for index := 0; index < value.Len(); index++ {
			wipeReflectValue(value.Index(index), seen)
		}
	case reflect.Struct:
		for _, field := range value.Fields() {
			field := field
			if field.CanInterface() {
				wipeReflectValue(field, seen)
			}
		}
	case reflect.Map:
		if value.IsNil() {
			return
		}
		iterator := value.MapRange()
		for iterator.Next() {
			wipeReflectValue(iterator.Value(), seen)
		}
	}
}

func assignDecoded(destination any, encoded wireValue, registry *CodecRegistry) error {
	pointer := reflect.ValueOf(destination)
	if !pointer.IsValid() || pointer.Kind() != reflect.Pointer || pointer.IsNil() {
		return fmt.Errorf("pkcs11 proxy: result destination must be a non-nil pointer")
	}
	value, err := decodeWireValue(encoded, pointer.Elem().Type(), registry)
	if err != nil {
		return err
	}
	pointer.Elem().Set(value)
	return nil
}

// applyArgumentUpdate copies provider-mutated pointer or parameter state back
// into the caller's original argument. Most Cryptoki arguments are input-only;
// this primarily covers CK_ASYNC_DATA and provider-written mechanism parameter
// buffers such as generated GCM IVs.
func applyArgumentUpdate(method string, index int, destination any, declared reflect.Type, encoded wireValue, registry *CodecRegistry) error {
	if destination == nil {
		return nil
	}
	if method == "AsyncJoin" && index == 3 {
		updated, err := decodeWireValue(encoded, declared, registry)
		if err != nil {
			return err
		}
		source := updated.Bytes()
		destinationBytes, ok := destination.([]byte)
		if !ok {
			return fmt.Errorf("pkcs11 proxy: AsyncJoin output destination has type %T", destination)
		}
		if len(source) > len(destinationBytes) {
			return fmt.Errorf("pkcs11 proxy: AsyncJoin returned %d bytes into a %d-byte buffer", len(source), len(destinationBytes))
		}
		copy(destinationBytes, source)
		return nil
	}
	if declared == anyType || declared.Kind() == reflect.Interface {
		if encoded.Kind == valueNil {
			return nil
		}
		if encoded.Kind != valueParameter {
			return fmt.Errorf("pkcs11 proxy: expected parameter update, got wire kind %d", encoded.Kind)
		}
		updated, err := decodeParameter(encoded.Parameter, registry)
		if err != nil {
			return err
		}
		copyParameterUpdate(destination, updated)
		return nil
	}

	pointer := reflect.ValueOf(destination)
	if pointer.Kind() != reflect.Pointer || pointer.IsNil() {
		// Input-only values are intentionally ignored.
		return nil
	}
	updated, err := decodeWireValue(encoded, declared, registry)
	if err != nil {
		return err
	}
	if updated.Kind() != reflect.Pointer || updated.IsNil() {
		return nil
	}
	pointer.Elem().Set(updated.Elem())
	return nil
}
