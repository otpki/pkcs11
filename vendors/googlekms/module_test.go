package googlekms

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func googleDevice(mechanisms ...uint) pkcs11.Device {
	inventory := make(map[raw.MechanismType]raw.MechanismInfo, len(mechanisms))
	for _, mechanism := range mechanisms {
		inventory[raw.MechanismType(mechanism)] = raw.MechanismInfo{}
	}
	return pkcs11.Device{Capabilities: pkcs11.Capabilities{Mechanisms: inventory}}
}

func TestNormalizeMechanismGeneratedIV(t *testing.T) {
	module := &Module{}
	original := &raw.GCMParams{AAD: []byte("aad")}
	adapted, err := module.NormalizeMechanism(pkcs11.VendorMechanismContext{Device: googleDevice(MechanismAESGCM)}, raw.NewMechanism(raw.CKM_AES_GCM, original))
	if err != nil {
		t.Fatal(err)
	}
	params := adapted.Parameter.(*raw.GCMParams)
	if adapted.Mechanism != MechanismAESGCM || len(params.IV) != 12 || params.IVBits != 96 || params.TagBits != 128 {
		t.Fatalf("adapted mechanism = %#v params=%#v", adapted, params)
	}
	if len(original.IV) != 0 || original.IVBits != 0 || original.TagBits != 0 {
		t.Fatalf("caller parameter was mutated: %#v", original)
	}
}

func TestNormalizeMechanismRejectsWrongIVSize(t *testing.T) {
	module := &Module{}
	_, err := module.NormalizeMechanism(pkcs11.VendorMechanismContext{Device: googleDevice(MechanismAESGCM)}, raw.NewMechanism(raw.CKM_AES_GCM, raw.GCMParams{IV: make([]byte, 16)}))
	if err == nil {
		t.Fatal("expected generated-IV buffer size error")
	}
}

func TestNormalizeTemplateGenerationAndCertificates(t *testing.T) {
	module := &Module{}
	public := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY),
		raw.NewAttribute(raw.CKA_VERIFY, true),
	}
	adapted, err := module.NormalizeTemplate(pkcs11.VendorTemplateContext{Operation: "C_GenerateKeyPair/public"}, public)
	if err != nil {
		t.Fatal(err)
	}
	if adapted != nil {
		t.Fatalf("public generation template = %#v, want nil", adapted)
	}
	if len(public) != 2 {
		t.Fatal("caller template was mutated")
	}
	_, err = module.NormalizeTemplate(pkcs11.VendorTemplateContext{}, []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_CERTIFICATE)})
	if err == nil {
		t.Fatal("expected writable certificate rejection")
	}
}

func TestGenerateOptionsAttributes(t *testing.T) {
	attributes, err := (GenerateOptions{Algorithm: AlgorithmAES256GCM, ProtectionLevel: ProtectionLevel(ProtectionHSM), CryptoKeyBackend: "projects/p/locations/l/keyRings/r/cryptoKeys/k"}).Attributes()
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 3 {
		t.Fatalf("attributes = %d, want 3", len(attributes))
	}
}
