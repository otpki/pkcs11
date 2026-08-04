package pkcs11

import (
	"errors"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestVendorNormalizationIsDelegatedWithoutMutatingCallerValues(t *testing.T) {
	const vendorMechanism = 0x80001000
	module := newTestVendor("normalizer", "Normalizer", 1, VendorMatchSpec{Manufacturers: []string{"normalizer"}})
	module.normalizeMechanism = func(context VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
		if context.Operation != "C_EncryptInit" {
			t.Fatalf("operation = %q", context.Operation)
		}
		mechanism.Mechanism = vendorMechanism
		return mechanism, nil
	}
	module.normalizeTemplate = func(_ VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
		return MergeAttributes(attributes, []*raw.Attribute{raw.NewAttribute(raw.CKA_DERIVE, true)}), nil
	}
	device := deviceForVendor(t, module, nil)
	originalMechanism := raw.NewMechanism(raw.CKM_AES_GCM, raw.GCMParams{IV: []byte{1, 2, 3}})
	adapted, err := normalizeVendorMechanism(device, "C_EncryptInit", originalMechanism)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism != vendorMechanism || originalMechanism.Mechanism != raw.CKM_AES_GCM {
		t.Fatalf("adapted=%#v original=%#v", adapted, originalMechanism)
	}
	originalTemplate := []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY)}
	adaptedTemplate, err := normalizeVendorTemplate(device, "C_GenerateKeyPair/private", originalTemplate)
	if err != nil {
		t.Fatal(err)
	}
	derive := false
	for _, attribute := range adaptedTemplate {
		if attribute != nil && attribute.Type == raw.CKA_DERIVE {
			derive, _ = raw.Bool(attribute.Value)
		}
	}
	if !derive || len(originalTemplate) != 1 {
		t.Fatalf("adapted=%#v original=%#v", adaptedTemplate, originalTemplate)
	}
}

func TestVendorErrorClassifierCannotWeakenStandardRecovery(t *testing.T) {
	module := newTestVendor("classifier", "Classifier", 1, VendorMatchSpec{Manufacturers: []string{"classifier"}})
	module.classifyError = func(context VendorErrorContext, _ error) RecoveryAction {
		if context.StandardAction != RecoveryReinitialize {
			t.Fatalf("standard action = %v", context.StandardAction)
		}
		return RecoveryNone
	}
	device := deviceForVendor(t, module, nil)
	if got := classifyVendorError(device, raw.Error(raw.CKR_DEVICE_ERROR), false); got != RecoveryReinitialize {
		t.Fatalf("action = %v, want reinitialize", got)
	}
}

func TestVendorErrorClassifierMayStrengthenUnknownErrors(t *testing.T) {
	module := newTestVendor("classifier", "Classifier", 1, VendorMatchSpec{Manufacturers: []string{"classifier"}})
	module.classifyError = func(context VendorErrorContext, _ error) RecoveryAction {
		if context.StandardAction != RecoveryNone {
			t.Fatalf("standard action = %v", context.StandardAction)
		}
		return RecoveryReplaceSession
	}
	device := deviceForVendor(t, module, nil)
	if got := classifyVendorError(device, errors.New("vendor transport reset"), false); got != RecoveryReplaceSession {
		t.Fatalf("action = %v", got)
	}
}
