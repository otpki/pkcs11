package securosys

import (
	"fmt"
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func template(keyType uint) []*raw.Attribute {
	return []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, keyType),
		raw.NewAttribute(raw.CKA_PARAMETER_SET, raw.CKP_ML_DSA_44),
	}
}

func TestNormalizeTemplateAddsPrimusPlaceholders(t *testing.T) {
	module := New()

	public, err := module.NormalizeTemplate(
		pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/public"}, template(raw.CKK_ML_DSA))
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttribute(public, raw.CKA_VALUE) {
		t.Fatal("public template is missing the CKA_VALUE placeholder")
	}
	if hasAttribute(public, raw.CKA_SEED) {
		t.Fatal("public template must not carry CKA_SEED")
	}

	private, err := module.NormalizeTemplate(
		pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/private"}, template(raw.CKK_ML_KEM))
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttribute(private, raw.CKA_VALUE) {
		t.Fatal("private template is missing the CKA_VALUE placeholder")
	}
	if !hasAttribute(private, raw.CKA_SEED) {
		t.Fatal("private template is missing the empty CKA_SEED placeholder")
	}
	if value := attributeValue(private, raw.CKA_SEED); len(value) != 0 {
		t.Fatalf("CKA_SEED placeholder must be present and empty, got %x", value)
	}
}

func TestNormalizeTemplateSkipsNonPQCAndOtherOperations(t *testing.T) {
	module := New()

	for _, keyType := range []uint{raw.CKK_RSA, raw.CKK_EC, raw.CKK_EC_EDWARDS, raw.CKK_GENERIC_SECRET} {
		result, err := module.NormalizeTemplate(
			pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/private"}, template(keyType))
		if err != nil {
			t.Fatalf("key type %#x: %v", keyType, err)
		}
		if len(result) != 3 || hasAttribute(result, raw.CKA_VALUE) || hasAttribute(result, raw.CKA_SEED) {
			t.Fatalf("key type %#x must not receive placeholders", keyType)
		}
	}

	for _, operation := range []string{"C_GenerateKey", "C_CreateObject", "C_UnwrapKey", "C_EncapsulateKey"} {
		result, err := module.NormalizeTemplate(
			pkcs11.VendorTemplateContext{Operation: operation}, template(raw.CKK_ML_DSA))
		if err != nil {
			t.Fatalf("operation %s: %v", operation, err)
		}
		if hasAttribute(result, raw.CKA_VALUE) || hasAttribute(result, raw.CKA_SEED) {
			t.Fatalf("operation %s must not receive placeholders", operation)
		}
	}
}

func TestNormalizeTemplatePreservesCallerValues(t *testing.T) {
	module := New()
	attributes := append(template(raw.CKK_SLH_DSA),
		raw.NewAttribute(raw.CKA_VALUE, []byte{0xde, 0xad}),
		raw.NewAttribute(raw.CKA_SEED, []byte{0x01, 0x02}),
	)
	result, err := module.NormalizeTemplate(
		pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/private"}, attributes)
	if err != nil {
		t.Fatal(err)
	}
	if got := attributeValue(result, raw.CKA_VALUE); len(got) != 2 || got[0] != 0xde {
		t.Fatalf("caller CKA_VALUE was overwritten: %x", got)
	}
	if got := attributeValue(result, raw.CKA_SEED); len(got) != 2 || got[0] != 0x01 {
		t.Fatalf("caller CKA_SEED was overwritten: %x", got)
	}
}

func attributeValue(attributes []*raw.Attribute, typ uint) []byte {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == typ {
			return attribute.Value
		}
	}
	return nil
}

func TestClassifyError(t *testing.T) {
	module := New()
	cases := []struct {
		name     string
		err      error
		standard pkcs11.RecoveryAction
		want     pkcs11.RecoveryAction
	}{
		{"not-logged-in triggers relogin", raw.Error(ErrorNotLoggedIn), pkcs11.RecoveryNone, pkcs11.RecoveryRelogin},
		{"unreachable replaces session", raw.Error(ErrorHSMUnreachable), pkcs11.RecoveryNone, pkcs11.RecoveryReplaceSession},
		{"wrong pin stays terminal", raw.Error(ErrorWrongPIN), pkcs11.RecoveryNone, pkcs11.RecoveryNone},
		{"setup password stays terminal", raw.Error(ErrorSetupPasswordLogin), pkcs11.RecoveryNone, pkcs11.RecoveryNone},
		{"vendor action cannot weaken standard", raw.Error(ErrorNotLoggedIn), pkcs11.RecoveryReinitialize, pkcs11.RecoveryReinitialize},
		{"wrapped vendor error", fmt.Errorf("sign: %w", raw.Error(ErrorHSMUnreachable)), pkcs11.RecoveryNone, pkcs11.RecoveryReplaceSession},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := module.ClassifyError(
				pkcs11.VendorErrorContext{StandardAction: testCase.standard}, testCase.err)
			if got != testCase.want {
				t.Fatalf("ClassifyError = %d, want %d", got, testCase.want)
			}
		})
	}
}
