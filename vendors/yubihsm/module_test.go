package yubihsm

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func TestNormalizeTemplateKeepsOnlyPolicyTheDeviceAccepts(t *testing.T) {
	module := New()
	input := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_MODIFIABLE, true),
		raw.NewAttribute(raw.CKA_COPYABLE, true),
		raw.NewAttribute(raw.CKA_DESTROYABLE, true),
		raw.NewAttribute(raw.CKA_ALWAYS_AUTHENTICATE, false),
		raw.NewAttribute(raw.CKA_SIGN, true),
	}
	adapted, err := module.NormalizeTemplate(pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/private"}, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []uint{raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_ALWAYS_AUTHENTICATE} {
		if hasAttribute(adapted, typ) {
			t.Fatalf("attribute %#x was not removed", typ)
		}
	}
	for _, typ := range []uint{raw.CKA_CLASS, raw.CKA_TOKEN, raw.CKA_DESTROYABLE, raw.CKA_SIGN} {
		if !hasAttribute(adapted, typ) {
			t.Fatalf("attribute %#x was removed", typ)
		}
	}
	if len(input) != 7 {
		t.Fatal("caller template was mutated")
	}
}

func TestNormalizeTemplateKeepsARequestedAlwaysAuthenticate(t *testing.T) {
	input := []*raw.Attribute{raw.NewAttribute(raw.CKA_ALWAYS_AUTHENTICATE, true)}
	adapted, err := New().NormalizeTemplate(pkcs11.VendorTemplateContext{}, input)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttribute(adapted, raw.CKA_ALWAYS_AUTHENTICATE) {
		t.Fatal("a true CKA_ALWAYS_AUTHENTICATE must reach the device, which refuses it")
	}
}

func hasAttribute(attributes []*raw.Attribute, typ uint) bool {
	for _, attribute := range attributes {
		if attribute.Type == typ {
			return true
		}
	}
	return false
}
