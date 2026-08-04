package ibm

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func TestNormalizeTemplateMirrorsParameterSet(t *testing.T) {
	module := &Module{}
	input := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_KEY_TYPE, KeyTypeMLDSA),
		raw.NewAttribute(raw.CKA_PARAMETER_SET, raw.CKP_ML_DSA_65),
	}
	adapted, err := module.NormalizeTemplate(pkcs11.VendorTemplateContext{}, input)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := pkcs11.AttributeULong(adapted, AttributeParameterSet)
	if !ok || value != raw.CKP_ML_DSA_65 {
		t.Fatalf("IBM parameter set = %#x, %t", value, ok)
	}
	if len(input) != 2 {
		t.Fatal("caller template was mutated")
	}
}

func TestInferAlgorithm(t *testing.T) {
	module := &Module{}
	algorithm, ok := module.InferAlgorithm(pkcs11.VendorObjectMetadata{
		KeyType: KeyTypeMLKEM,
		Attributes: []*raw.Attribute{
			raw.NewAttribute(AttributeParameterSet, raw.CKP_ML_KEM_768),
		},
	})
	if !ok || algorithm != pkcs11.AlgorithmMLKEM768 {
		t.Fatalf("InferAlgorithm = %q, %t", algorithm, ok)
	}
}

func TestMLKEMParamsNativeLayout(t *testing.T) {
	params := &MLKEMParams{
		Version: 1, Mode: MLKEMEncapsulate, KDF: raw.CKD_SHA256_KDF,
		Prepend: true, Cipher: []byte{1, 2}, SharedData: []byte{3, 4}, Secret: 7,
	}
	for _, abi := range []raw.NativeABI{
		{ULongSize: 8, PointerSize: 8, ByteOrder: raw.HostNativeABI().ByteOrder},
		{ULongSize: 4, PointerSize: 8, ByteOrder: raw.HostNativeABI().ByteOrder},
	} {
		layout, err := params.MarshalPKCS11Native(abi)
		if err != nil {
			t.Fatal(err)
		}
		if len(layout.Root) == 0 || len(layout.Pointers) != 2 {
			t.Fatalf("layout = root:%d pointers:%d", len(layout.Root), len(layout.Pointers))
		}
	}
}
