package raw

import (
	"fmt"
	"math/big"
	"time"
)

// Attribute is a PKCS#11 CK_ATTRIBUTE. Children represents an array-valued
// attribute such as CKA_WRAP_TEMPLATE or CKA_DERIVE_TEMPLATE.
type Attribute struct {
	Type     uint
	Value    []byte
	Children []*Attribute
}

// Date encodes the fixed-width CK_DATE representation.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

func (d Date) bytes() ([]byte, error) {
	if d.Year < 0 || d.Year > 9999 || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
		return nil, fmt.Errorf("pkcs11: invalid CK_DATE %04d-%02d-%02d", d.Year, d.Month, d.Day)
	}
	return fmt.Appendf(nil, "%04d%02d%02d", d.Year, d.Month, d.Day), nil
}

// NewAttribute follows miekg/pkcs11's constructor style. Integer values are
// encoded as native CK_ULONG values; big.Int values are unsigned big-endian.
func NewAttribute(typ uint, value any) *Attribute {
	attribute := &Attribute{Type: typ}
	switch v := value.(type) {
	case nil:
	case []byte:
		attribute.Value = append([]byte(nil), v...)
	case string:
		attribute.Value = []byte(v)
	case bool:
		if v {
			attribute.Value = []byte{1}
		} else {
			attribute.Value = []byte{0}
		}
	case uint:
		attribute.Value = nativeULong(v)
	case uint8:
		attribute.Value = nativeULong(uint(v))
	case uint16:
		attribute.Value = nativeULong(uint(v))
	case uint32:
		attribute.Value = nativeULong(uint(v))
	case uint64:
		attribute.Value = nativeULong(uint(v))
	case int:
		attribute.Value = nativeULong(uint(v))
	case int32:
		attribute.Value = nativeULong(uint(v))
	case int64:
		attribute.Value = nativeULong(uint(v))
	case *big.Int:
		if v != nil {
			attribute.Value = v.Bytes()
		}
	case big.Int:
		attribute.Value = v.Bytes()
	case Date:
		attribute.Value, _ = v.bytes()
	case time.Time:
		attribute.Value = []byte(v.UTC().Format("20060102"))
	case []uint:
		attribute.Value = nativeULongs(v)
	default:
		panic(fmt.Sprintf("pkcs11: unsupported attribute value %T", value))
	}
	return attribute
}

func NewTemplateAttribute(typ uint, children ...*Attribute) *Attribute {
	return &Attribute{Type: typ, Children: append([]*Attribute(nil), children...)}
}

// ULong decodes a native-width CK_ULONG attribute value.
func ULong(value []byte) (uint, bool) { return ulongFromBytes(value) }

// Bool decodes a CK_BBOOL attribute value.
func Bool(value []byte) (bool, bool) {
	if len(value) != 1 {
		return false, false
	}
	return value[0] != 0, true
}
