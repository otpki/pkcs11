package pkcs11

import (
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func attributeTypes(attributes []*raw.Attribute) map[uint]bool {
	types := make(map[uint]bool, len(attributes))
	for _, attribute := range attributes {
		if attribute != nil {
			types[attribute.Type] = true
		}
	}
	return types
}

func TestPolicyAttributesAreValidForObjectClass(t *testing.T) {
	policy := ObjectPolicy{
		Token:              true,
		Private:            true,
		Sensitive:          true,
		Extractable:        false,
		Modifiable:         true,
		Copyable:           true,
		Destroyable:        true,
		AlwaysAuthenticate: true,
	}

	tests := []struct {
		name    string
		class   uint
		present []uint
		absent  []uint
	}{
		{
			name:    "public key",
			class:   raw.CKO_PUBLIC_KEY,
			present: []uint{raw.CKA_TOKEN, raw.CKA_PRIVATE, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE},
			absent:  []uint{raw.CKA_SENSITIVE, raw.CKA_EXTRACTABLE, raw.CKA_ALWAYS_AUTHENTICATE},
		},
		{
			name:    "secret key",
			class:   raw.CKO_SECRET_KEY,
			present: []uint{raw.CKA_TOKEN, raw.CKA_PRIVATE, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE, raw.CKA_SENSITIVE, raw.CKA_EXTRACTABLE},
			absent:  []uint{raw.CKA_ALWAYS_AUTHENTICATE},
		},
		{
			name:    "private key",
			class:   raw.CKO_PRIVATE_KEY,
			present: []uint{raw.CKA_TOKEN, raw.CKA_PRIVATE, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE, raw.CKA_SENSITIVE, raw.CKA_EXTRACTABLE, raw.CKA_ALWAYS_AUTHENTICATE},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			types := attributeTypes(policyAttributes(policy, test.class))
			for _, typ := range test.present {
				if !types[typ] {
					t.Errorf("attribute %#x is missing", typ)
				}
			}
			for _, typ := range test.absent {
				if types[typ] {
					t.Errorf("attribute %#x is invalid for class %#x", typ, test.class)
				}
			}
		})
	}
}
