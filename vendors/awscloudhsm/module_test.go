package awscloudhsm

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func awsDevice(mechanisms ...uint) pkcs11.Device {
	inventory := make(map[raw.MechanismType]raw.MechanismInfo, len(mechanisms))
	for _, mechanism := range mechanisms {
		inventory[raw.MechanismType(mechanism)] = raw.MechanismInfo{}
	}
	return pkcs11.Device{Capabilities: pkcs11.Capabilities{Mechanisms: inventory}}
}

func TestNormalizeMechanismCloudHSMGCM(t *testing.T) {
	module := &Module{}
	original := &raw.GCMParams{IV: []byte("caller-owned"), IVBits: 96, AAD: []byte("aad")}
	mechanism := raw.NewMechanism(raw.CKM_AES_GCM, original)
	adapted, err := module.NormalizeMechanism(pkcs11.VendorMechanismContext{Device: awsDevice(MechanismAESGCM)}, mechanism)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism != MechanismAESGCM {
		t.Fatalf("mechanism = %#x, want %#x", adapted.Mechanism, MechanismAESGCM)
	}
	params, ok := adapted.Parameter.(*raw.GCMParams)
	if !ok || params == nil {
		t.Fatalf("parameter = %T, want *raw.GCMParams", adapted.Parameter)
	}
	if params.IV != nil || params.IVBits != 0 || params.TagBits != 128 {
		t.Fatalf("adapted GCM params = %#v", params)
	}
	if string(original.IV) != "caller-owned" || original.IVBits != 96 || original.TagBits != 0 {
		t.Fatalf("caller parameter was mutated: %#v", original)
	}
	if mechanism.Mechanism != raw.CKM_AES_GCM {
		t.Fatalf("caller mechanism was mutated")
	}
}

func TestNormalizeMechanismRejectsOAEPLabel(t *testing.T) {
	module := &Module{}
	_, err := module.NormalizeMechanism(pkcs11.VendorMechanismContext{}, raw.NewMechanism(raw.CKM_RSA_PKCS_OAEP, raw.OAEPParams{SourceData: []byte("label")}))
	if err == nil {
		t.Fatal("expected non-empty OAEP label rejection")
	}
}

func TestFinalizeEncryptionDocumentsCiphertextPrefix(t *testing.T) {
	module := &Module{}
	result, err := module.FinalizeEncryption(pkcs11.VendorCipherContext{
		Device: awsDevice(MechanismAESGCM),
		Route:  pkcs11.Route{Mechanism: raw.NewMechanism(raw.CKM_AES_GCM, nil)},
	}, pkcs11.EncryptionResult{Ciphertext: []byte("iv+ciphertext"), IV: []byte("separate")})
	if err != nil {
		t.Fatal(err)
	}
	if result.IV != nil {
		t.Fatalf("IV = %x, want nil because CloudHSM prefixes it", result.IV)
	}
}
