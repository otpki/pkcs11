package utimaco

import (
	"bytes"
	"crypto"
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

func utimacoDevice(mechanisms ...uint) pkcs11.Device {
	inventory := make(map[raw.MechanismType]raw.MechanismInfo, len(mechanisms))
	for _, mechanism := range mechanisms {
		inventory[raw.MechanismType(mechanism)] = raw.MechanismInfo{}
	}
	return pkcs11.Device{
		Adapter: pkcs11.AdapterInfo{Family: ID, Name: "Utimaco QuantumProtect"},
		Capabilities: pkcs11.Capabilities{
			Mechanisms: inventory,
			Algorithms: make(map[pkcs11.Algorithm]pkcs11.AlgorithmCapability),
		},
	}
}

func TestMatchUtimacoVariants(t *testing.T) {
	module := &Module{}
	tests := []struct {
		name        string
		fingerprint pkcs11.Fingerprint
		variant     string
	}{
		{
			name: "cryptoserver",
			fingerprint: pkcs11.Fingerprint{
				Module: raw.Info{ManufacturerID: "Utimaco", LibraryDescription: "CryptoServer PKCS11"},
			},
			variant: "cryptoserver",
		},
		{
			name: "utrust quantumprotect",
			fingerprint: pkcs11.Fingerprint{
				Module: raw.Info{ManufacturerID: "Utimaco", LibraryDescription: "u.trust"},
				Mechanisms: map[raw.MechanismType]raw.MechanismInfo{
					raw.MechanismType(MechanismMLDSAKeyPairGen): {},
				},
			},
			variant: "u.trust+quantumprotect",
		},
		{
			name: "cp5",
			fingerprint: pkcs11.Fingerprint{
				Module: raw.Info{ManufacturerID: "Utimaco", LibraryDescription: "CP5"},
			},
			variant: "cp5",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := module.Definition().MatchFunc(test.fingerprint)
			if !match.Matched || match.Variant != test.variant {
				t.Fatalf("match = %#v, want variant %q", match, test.variant)
			}
		})
	}
	if match := module.Definition().MatchFunc(pkcs11.Fingerprint{Module: raw.Info{ManufacturerID: "other"}}); match.Matched {
		t.Fatalf("unexpected match: %#v", match)
	}
}

func TestAdaptRoutePrefersStandardRoute(t *testing.T) {
	module := &Module{}
	standard := pkcs11.Route{
		Intent:          pkcs11.Intent{Operation: pkcs11.OperationSign, Algorithm: pkcs11.AlgorithmMLDSA65},
		Mechanism:       raw.NewMechanism(raw.CKM_ML_DSA, raw.SignAdditionalContext{}),
		MechanismSource: "pkcs11-standard",
		KeyType:         raw.CKK_ML_DSA,
		ParameterSet:    raw.CKP_ML_DSA_65,
	}
	adapted, err := module.AdaptRoute(utimacoDevice(MechanismMLDSASign), standard)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism.Mechanism != raw.CKM_ML_DSA || adapted.MechanismSource != "pkcs11-standard" {
		t.Fatalf("standard route was replaced: %#v", adapted)
	}
}

func TestAdaptRouteMLDSAGeneration(t *testing.T) {
	module := &Module{}
	route := pkcs11.Route{
		Intent:          pkcs11.Intent{Operation: pkcs11.OperationGenerate, Algorithm: pkcs11.AlgorithmMLDSA65},
		Mechanism:       raw.NewMechanism(MechanismMLDSAKeyPairGen, nil),
		MechanismSource: "vendor-adapter",
	}
	adapted, err := module.AdaptRoute(utimacoDevice(MechanismMLDSAKeyPairGen), route)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism.Mechanism != MechanismMLDSAKeyPairGen || adapted.KeyType != KeyTypeMLDSA || adapted.ParameterSet != uint(ParameterSet65Or768) || !adapted.OmitParameterSetAttribute {
		t.Fatalf("adapted route = %#v", adapted)
	}
	parameter, ok := adapted.Mechanism.Parameter.([]byte)
	if !ok {
		t.Fatalf("parameter = %T", adapted.Mechanism.Parameter)
	}
	want := []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0}
	if !bytes.Equal(parameter, want) {
		t.Fatalf("parameter = %x, want %x", parameter, want)
	}
}

func TestAdaptRouteMLDSASignModes(t *testing.T) {
	module := &Module{}
	device := utimacoDevice(MechanismMLDSASign, MechanismMLDSAExternalMuSign)

	prehash := pkcs11.Route{
		Intent: pkcs11.Intent{
			Operation: pkcs11.OperationSign, Algorithm: pkcs11.AlgorithmMLDSA44,
			Hash: crypto.SHA256, Prehashed: true, Hedge: pkcs11.HedgePreferred,
		},
		Mechanism: raw.NewMechanism(MechanismMLDSASign, nil), MechanismSource: "vendor-adapter",
	}
	adapted, err := module.AdaptRoute(device, prehash)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xf2, 0x04, 0x00, 0x01, 0, 0, 0, 1}
	if parameter := adapted.Mechanism.Parameter.([]byte); !bytes.Equal(parameter, want) {
		t.Fatalf("prehash parameter = %x, want %x", parameter, want)
	}

	externalMu := pkcs11.Route{
		Intent: pkcs11.Intent{
			Operation: pkcs11.OperationSign, Algorithm: pkcs11.AlgorithmMLDSA87,
			ExternalMu: true, Hedge: pkcs11.HedgePreferred,
		},
		Mechanism: raw.NewMechanism(MechanismMLDSAExternalMuSign, nil), MechanismSource: "vendor-adapter",
	}
	adapted, err = module.AdaptRoute(device, externalMu)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism.Mechanism != MechanismMLDSAExternalMuSign {
		t.Fatalf("external-mu mechanism = %#x", adapted.Mechanism.Mechanism)
	}

	contextRoute := prehash
	contextRoute.Intent.Prehashed = false
	contextRoute.Intent.Hash = 0
	contextRoute.Intent.Context = []byte("ctx")
	if _, err := module.AdaptRoute(device, contextRoute); err == nil {
		t.Fatal("expected unsupported context error")
	}
}

func TestAdaptRouteMLKEMAndHBSExecution(t *testing.T) {
	module := &Module{}
	kem, err := module.AdaptRoute(utimacoDevice(MechanismMLKEMEncapsulate), pkcs11.Route{
		Intent:    pkcs11.Intent{Operation: pkcs11.OperationEncapsulate, Algorithm: pkcs11.AlgorithmMLKEM768},
		Mechanism: raw.NewMechanism(MechanismMLKEMEncapsulate, nil), MechanismSource: "vendor-adapter",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, ok := kem.VendorData.(routeData)
	if !ok || data.Kind != routeKindDeriveKEM || data.Set != ParameterSet65Or768 || !kem.Execution.ReadWrite || kem.Execution.Replay != pkcs11.RouteReplayNever {
		t.Fatalf("KEM route = %#v data=%#v", kem, data)
	}

	hbs, err := module.AdaptRoute(utimacoDevice(MechanismHSSSign), pkcs11.Route{
		Intent: pkcs11.Intent{Operation: pkcs11.OperationSign, Algorithm: pkcs11.AlgorithmHSS},
	})
	if err != nil {
		t.Fatal(err)
	}
	model, handled := module.KeyPairModel(pkcs11.AlgorithmHSS, hbs)
	if !handled || !model.SingleObject || model.ObjectClass != raw.CKO_SECRET_KEY || model.KeyType != raw.CKK_GENERIC_SECRET {
		t.Fatalf("HBS model = %#v handled=%t", model, handled)
	}
	if !hbs.Execution.ReadWrite || hbs.Execution.Replay != pkcs11.RouteReplayNever {
		t.Fatalf("HBS execution = %#v", hbs.Execution)
	}
}

func TestNormalizeTemplateMLAlgorithms(t *testing.T) {
	module := &Module{}
	input := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, KeyTypeMLKEM),
		raw.NewAttribute(raw.CKA_PARAMETER_SET, raw.CKP_ML_KEM_768),
		raw.NewAttribute(raw.CKA_DECAPSULATE, true),
	}
	adapted, err := module.NormalizeTemplate(pkcs11.VendorTemplateContext{}, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkcs11.AttributeULong(adapted, raw.CKA_PARAMETER_SET); ok {
		t.Fatal("CKA_PARAMETER_SET was not removed")
	}
	if _, ok := pkcs11.AttributeULong(adapted, raw.CKA_DECAPSULATE); ok {
		t.Fatal("CKA_DECAPSULATE was not removed")
	}
	derivePresent := false
	for _, attribute := range adapted {
		if attribute != nil && attribute.Type == raw.CKA_DERIVE {
			derive, ok := raw.Bool(attribute.Value)
			derivePresent = ok && derive
		}
	}
	if !derivePresent {
		t.Fatal("CKA_DERIVE was not added")
	}
	if len(input) != 4 {
		t.Fatal("caller template was mutated")
	}
}

func TestInferAlgorithmAndCapabilities(t *testing.T) {
	module := &Module{}
	algorithm, ok := module.InferAlgorithm(pkcs11.VendorObjectMetadata{
		KeyType: KeyTypeMLDSA,
		Attributes: []*raw.Attribute{
			raw.NewAttribute(AttributeCustomData, make([]byte, 1952)),
		},
	})
	if !ok || algorithm != pkcs11.AlgorithmMLDSA65 {
		t.Fatalf("InferAlgorithm = %q, %t", algorithm, ok)
	}

	fingerprint := pkcs11.Fingerprint{Mechanisms: map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(MechanismMLDSAKeyPairGen): {},
		raw.MechanismType(MechanismMLDSASign):       {},
		raw.MechanismType(MechanismMLDSAVerify):     {},
	}}
	capabilities := pkcs11.Capabilities{Algorithms: make(map[pkcs11.Algorithm]pkcs11.AlgorithmCapability)}
	module.AugmentCapabilities(fingerprint, &capabilities)
	capability := capabilities.Algorithms[pkcs11.AlgorithmMLDSA65]
	if !capability.KeyGeneration || !capability.Sign || !capability.Verify || !capabilities.PQC || !capabilities.MLDSA {
		t.Fatalf("capabilities = %#v", capabilities)
	}
}
