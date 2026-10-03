package smartcardhsm

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func TestNormalizeTemplateStripsUnsupportedPolicy(t *testing.T) {
	module := &Module{}
	input := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY),
		raw.NewAttribute(raw.CKA_MODIFIABLE, true),
		raw.NewAttribute(raw.CKA_COPYABLE, true),
		raw.NewAttribute(raw.CKA_DESTROYABLE, true),
		raw.NewAttribute(raw.CKA_SIGN, true),
	}
	adapted, err := module.NormalizeTemplate(pkcs11.VendorTemplateContext{}, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []uint{raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE} {
		if _, ok := pkcs11.AttributeULong(adapted, typ); ok {
			t.Fatalf("attribute %#x was not removed", typ)
		}
	}
	if len(input) != 5 {
		t.Fatal("caller template was mutated")
	}
}
