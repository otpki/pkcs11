package pkcs11

import (
	"crypto"
	"encoding/asn1"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func testDevice(definition adapterDefinition, mechanisms map[raw.MechanismType]raw.MechanismInfo) Device {
	return Device{
		Fingerprint: Fingerprint{Token: raw.TokenInfo{Label: "test"}, Mechanisms: mechanisms},
		Adapter:     AdapterInfo{Name: definition.name, Family: definition.family},
		definition:  definition,
		plan:        definition.behavior,
	}
}

func TestResolveRouteRSAKeyPairMechanismZero(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_RSA_PKCS_KEY_PAIR_GEN): {Flags: raw.CKF_GENERATE_KEY_PAIR},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism == nil || route.Mechanism.Mechanism != raw.CKM_RSA_PKCS_KEY_PAIR_GEN {
		t.Fatalf("mechanism = %#v, want CKM_RSA_PKCS_KEY_PAIR_GEN (%d)", route.Mechanism, raw.CKM_RSA_PKCS_KEY_PAIR_GEN)
	}
	if route.KeyType != raw.CKK_RSA {
		t.Fatalf("key type = %d, want CKK_RSA (%d)", route.KeyType, raw.CKK_RSA)
	}
}

func TestResolveRSAOAEPSHA1(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_RSA_PKCS_OAEP): {Flags: raw.CKF_ENCRYPT},
	})
	route, err := ResolveRoute(device, Intent{
		Operation:  OperationEncrypt,
		Algorithm:  AlgorithmRSA,
		RSAPadding: RSAPaddingOAEP,
		Hash:       crypto.SHA1,
	})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism == nil || route.Mechanism.Mechanism != raw.CKM_RSA_PKCS_OAEP {
		t.Fatalf("mechanism = %#v, want CKM_RSA_PKCS_OAEP", route.Mechanism)
	}
	parameters, ok := route.Mechanism.Parameter.(raw.OAEPParams)
	if !ok {
		t.Fatalf("parameter type = %T, want raw.OAEPParams", route.Mechanism.Parameter)
	}
	if parameters.HashAlg != raw.CKM_SHA_1 || parameters.MGF != raw.CKG_MGF1_SHA1 || parameters.Source != raw.CKZ_DATA_SPECIFIED {
		t.Fatalf("OAEP parameters = %#v", parameters)
	}
}

func TestResolveVendorDilithiumRoute(t *testing.T) {
	const (
		keyType   = 0x80001001
		keygen    = 0x80001002
		parameter = 0x80001003
	)
	definition := adapterDefinition{name: "vendor", identifiers: identifierAliases{
		keyTypes:      map[string]NumericID{"dilithium": keyType},
		mechanisms:    map[string]NumericID{"dilithium-key-pair-gen": keygen},
		parameterSets: map[string]NumericID{"dilithium-2": parameter},
	}}
	device := testDevice(definition, map[raw.MechanismType]raw.MechanismInfo{
		keygen: {Flags: raw.CKF_GENERATE_KEY_PAIR},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmDilithium2})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.KeyType != keyType || route.ParameterSet != parameter || route.Mechanism.Mechanism != keygen {
		t.Fatalf("unexpected route: keyType=%#x parameter=%#x mechanism=%#x", route.KeyType, route.ParameterSet, route.Mechanism.Mechanism)
	}
}

func TestResolveExternalMu(t *testing.T) {
	const mechanism = 0x80002001
	definition := adapterDefinition{name: "vendor", identifiers: identifierAliases{mechanisms: map[string]NumericID{"ml-dsa-external-mu": mechanism}}}
	device := testDevice(definition, map[raw.MechanismType]raw.MechanismInfo{
		mechanism: {Flags: raw.CKF_SIGN},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmMLDSA65, ExternalMu: true})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism.Mechanism != mechanism {
		t.Fatalf("mechanism = %#x, want %#x", route.Mechanism.Mechanism, mechanism)
	}
}

func TestResolveMLDSAPrehash(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_HASH_ML_DSA): {Flags: raw.CKF_SIGN},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmMLDSA44, Hash: crypto.SHA256, Prehashed: true})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism.Mechanism != raw.CKM_HASH_ML_DSA {
		t.Fatalf("mechanism = %#x, want CKM_HASH_ML_DSA", route.Mechanism.Mechanism)
	}
	if _, ok := route.Mechanism.Parameter.(raw.HashSignAdditionalContext); !ok {
		t.Fatalf("parameter type = %T", route.Mechanism.Parameter)
	}
}

func TestResolveEdDSAParameters(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_EDDSA): {Flags: raw.CKF_SIGN},
	})

	pure, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmEd25519})
	if err != nil {
		t.Fatal(err)
	}
	if pure.Mechanism.Parameter != nil {
		t.Fatalf("pure Ed25519 parameter = %#v, want nil", pure.Mechanism.Parameter)
	}

	contextual, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmEd25519, Context: []byte("ctx")})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := contextual.Mechanism.Parameter.(raw.EdDSAParams); !ok {
		t.Fatalf("contextual Ed25519 parameter = %T, want raw.EdDSAParams", contextual.Mechanism.Parameter)
	}

	ed448, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmEd448})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ed448.Mechanism.Parameter.(raw.EdDSAParams); !ok {
		t.Fatalf("Ed448 parameter = %T, want raw.EdDSAParams", ed448.Mechanism.Parameter)
	}
}

func TestResolvePQCGenerationParameterSetIsPublicOnly(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_ML_DSA_KEY_PAIR_GEN): {Flags: raw.CKF_GENERATE_KEY_PAIR},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := invariantValue(route.PublicTemplate, raw.CKA_PARAMETER_SET); !ok {
		t.Fatal("public generation template lacks CKA_PARAMETER_SET")
	}
	if _, ok := invariantValue(route.PrivateTemplate, raw.CKA_PARAMETER_SET); ok {
		t.Fatal("private generation template contains read-only CKA_PARAMETER_SET")
	}
}

func TestResolveGenerationMechanismOverride(t *testing.T) {
	mechanism := uint(0x8000f123)
	device := testDevice(adapterDefinition{name: "generic"}, nil)
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmRSA, MechanismOverride: &mechanism, MechanismParameter: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mechanism.Mechanism != mechanism || route.MechanismSource != "caller-override" {
		t.Fatalf("unexpected route: %#v", route)
	}
	if route.KeyType != raw.CKK_RSA || len(route.PublicTemplate) == 0 || len(route.PrivateTemplate) == 0 {
		t.Fatalf("override lost standard RSA templates: %#v", route)
	}
}

func TestResolveKEMMechanismOverride(t *testing.T) {
	mechanism := uint(0x8000f456)
	device := testDevice(adapterDefinition{name: "generic"}, nil)
	route, err := ResolveRoute(device, Intent{Operation: OperationEncapsulate, Algorithm: AlgorithmKyber768, MechanismOverride: &mechanism})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mechanism.Mechanism != mechanism {
		t.Fatalf("mechanism = %#x, want %#x", route.Mechanism.Mechanism, mechanism)
	}
}

func TestInferAlgorithmFromStandardAttributes(t *testing.T) {
	marshalOID := func(oid asn1.ObjectIdentifier) []byte {
		value, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatalf("marshal OID %v: %v", oid, err)
		}
		return value
	}
	ulong := func(value uint) []byte { return raw.NewAttribute(0, value).Value }

	tests := []struct {
		name       string
		keyType    uint
		attributes []*raw.Attribute
		want       Algorithm
	}{
		{
			name:    "P-384",
			keyType: raw.CKK_EC,
			attributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_EC_PARAMS, marshalOID(asn1.ObjectIdentifier{1, 3, 132, 0, 34})),
			},
			want: AlgorithmECDSAP384,
		},
		{
			name:    "P-521",
			keyType: raw.CKK_EC,
			attributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_EC_PARAMS, marshalOID(asn1.ObjectIdentifier{1, 3, 132, 0, 35})),
			},
			want: AlgorithmECDSAP521,
		},
		{
			name:    "Ed448",
			keyType: raw.CKK_EC_EDWARDS,
			attributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_EC_PARAMS, marshalOID(asn1.ObjectIdentifier{1, 3, 101, 113})),
			},
			want: AlgorithmEd448,
		},
		{
			name:    "AES-256",
			keyType: raw.CKK_AES,
			attributes: []*raw.Attribute{
				{Type: raw.CKA_VALUE_LEN, Value: ulong(32)},
			},
			want: AlgorithmAES256,
		},
		{
			name:    "SLH-DSA-SHAKE-256f",
			keyType: raw.CKK_SLH_DSA,
			attributes: []*raw.Attribute{
				{Type: raw.CKA_PARAMETER_SET, Value: ulong(raw.CKP_SLH_DSA_SHAKE_256F)},
			},
			want: AlgorithmSLHDSASHAKE256F,
		},
		{
			name:    "unknown EC curve",
			keyType: raw.CKK_EC,
			attributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_EC_PARAMS, marshalOID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1})),
			},
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := inferAlgorithm(testDevice(adapterDefinition{name: "generic"}, nil), test.keyType, test.attributes); got != test.want {
				t.Fatalf("inferAlgorithm() = %q, want %q", got, test.want)
			}
		})
	}
}
