package pkcs11

import (
	"bytes"
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

func TestResolveRSASHA3Routes(t *testing.T) {
	hashes := []struct {
		hash     crypto.Hash
		pkcs1v15 uint
		pss      uint
		digest   uint
		mgf      uint
	}{
		{crypto.SHA3_224, raw.CKM_SHA3_224_RSA_PKCS, raw.CKM_SHA3_224_RSA_PKCS_PSS, raw.CKM_SHA3_224, raw.CKG_MGF1_SHA3_224},
		{crypto.SHA3_256, raw.CKM_SHA3_256_RSA_PKCS, raw.CKM_SHA3_256_RSA_PKCS_PSS, raw.CKM_SHA3_256, raw.CKG_MGF1_SHA3_256},
		{crypto.SHA3_384, raw.CKM_SHA3_384_RSA_PKCS, raw.CKM_SHA3_384_RSA_PKCS_PSS, raw.CKM_SHA3_384, raw.CKG_MGF1_SHA3_384},
		{crypto.SHA3_512, raw.CKM_SHA3_512_RSA_PKCS, raw.CKM_SHA3_512_RSA_PKCS_PSS, raw.CKM_SHA3_512, raw.CKG_MGF1_SHA3_512},
	}
	mechanisms := map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_RSA_PKCS):     {Flags: raw.CKF_SIGN | raw.CKF_VERIFY},
		raw.MechanismType(raw.CKM_RSA_PKCS_PSS): {Flags: raw.CKF_SIGN | raw.CKF_VERIFY},
	}
	for _, hash := range hashes {
		mechanisms[raw.MechanismType(hash.pkcs1v15)] = raw.MechanismInfo{Flags: raw.CKF_SIGN | raw.CKF_VERIFY}
		mechanisms[raw.MechanismType(hash.pss)] = raw.MechanismInfo{Flags: raw.CKF_SIGN | raw.CKF_VERIFY}
	}
	device := testDevice(adapterDefinition{name: "generic"}, mechanisms)
	for _, hash := range hashes {
		for _, operation := range []Operation{OperationSign, OperationVerify} {
			t.Run(hash.hash.String()+"/"+string(operation), func(t *testing.T) {
				for _, test := range []struct {
					name      string
					intent    Intent
					mechanism uint
					params    *raw.PSSParams
				}{
					{
						"message-pkcs1v15",
						Intent{Operation: operation, Algorithm: AlgorithmRSA, Hash: hash.hash, RSAPadding: RSAPaddingPKCS1v15},
						hash.pkcs1v15, nil,
					},
					{
						"message-pss",
						Intent{Operation: operation, Algorithm: AlgorithmRSA, Hash: hash.hash, RSAPadding: RSAPaddingPSS},
						hash.pss, &raw.PSSParams{HashAlg: hash.digest, MGF: hash.mgf, SaltLen: uint(hash.hash.Size())},
					},
					{
						"prehashed-pss",
						Intent{Operation: operation, Algorithm: AlgorithmRSA, Hash: hash.hash, Prehashed: true, RSAPadding: RSAPaddingPSS},
						raw.CKM_RSA_PKCS_PSS, &raw.PSSParams{HashAlg: hash.digest, MGF: hash.mgf, SaltLen: uint(hash.hash.Size())},
					},
					{
						"prehashed-pkcs1v15",
						Intent{Operation: operation, Algorithm: AlgorithmRSA, Hash: hash.hash, Prehashed: true, RSAPadding: RSAPaddingPKCS1v15},
						raw.CKM_RSA_PKCS, nil,
					},
				} {
					t.Run(test.name, func(t *testing.T) {
						route, err := ResolveRoute(device, test.intent)
						if err != nil {
							t.Fatalf("ResolveRoute: %v", err)
						}
						if route.Mechanism == nil || route.Mechanism.Mechanism != test.mechanism {
							t.Fatalf("mechanism = %#v, want %#x", route.Mechanism, test.mechanism)
						}
						if test.params == nil {
							return
						}
						params, ok := route.Mechanism.Parameter.(raw.PSSParams)
						if !ok {
							t.Fatalf("parameter type = %T, want raw.PSSParams", route.Mechanism.Parameter)
						}
						if *test.params != params {
							t.Fatalf("PSS parameters = %#v, want %#v", params, *test.params)
						}
					})
				}
			})
		}
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

func TestResolvePQCGenerationParameterSetOnBothTemplates(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_ML_DSA_KEY_PAIR_GEN): {Flags: raw.CKF_GENERATE_KEY_PAIR},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	// PKCS #11 3.2 lists CKA_PARAMETER_SET in both generation templates and
	// every observed v3.2 provider (Securosys Primus, Entrust nShield) requires
	// it on the private template too.
	for name, template := range map[string][]*raw.Attribute{"public": route.PublicTemplate, "private": route.PrivateTemplate} {
		value, ok := invariantValue(template, raw.CKA_PARAMETER_SET)
		if !ok {
			t.Fatalf("%s generation template lacks CKA_PARAMETER_SET", name)
		}
		if actual, valid := raw.ULong(value); !valid || actual != raw.CKP_ML_DSA_65 {
			t.Fatalf("%s template CKA_PARAMETER_SET = %x, want %x", name, value, raw.CKP_ML_DSA_65)
		}
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

func TestResolveChaCha20KeyGen(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_CHACHA20_KEY_GEN): {Flags: raw.CKF_GENERATE},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmChaCha20})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism == nil || route.Mechanism.Mechanism != raw.CKM_CHACHA20_KEY_GEN {
		t.Fatalf("mechanism = %#v, want CKM_CHACHA20_KEY_GEN", route.Mechanism)
	}
	if route.KeyType != raw.CKK_CHACHA20 {
		t.Fatalf("key type = %#x, want CKK_CHACHA20", route.KeyType)
	}
}

func TestResolveChaCha20Poly1305Default(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_CHACHA20_POLY1305): {Flags: raw.CKF_ENCRYPT},
		raw.MechanismType(raw.CKM_CHACHA20):          {Flags: raw.CKF_ENCRYPT},
	})
	route, err := ResolveRoute(device, Intent{
		Operation: OperationEncrypt,
		Algorithm: AlgorithmChaCha20,
		IV:        make([]byte, 12),
		AAD:       []byte("aad"),
	})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism.Mechanism != raw.CKM_CHACHA20_POLY1305 {
		t.Fatalf("mechanism = %#x, want CKM_CHACHA20_POLY1305", route.Mechanism.Mechanism)
	}
	parameters, ok := route.Mechanism.Parameter.(raw.ChaCha20Poly1305Params)
	if !ok {
		t.Fatalf("parameter type = %T, want raw.ChaCha20Poly1305Params", route.Mechanism.Parameter)
	}
	if len(parameters.Nonce) != 12 || string(parameters.AAD) != "aad" {
		t.Fatalf("parameters = %#v", parameters)
	}
}

func TestResolveChaCha20Stream(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_CHACHA20): {Flags: raw.CKF_ENCRYPT},
	})
	iv := append([]byte{1, 0, 0, 0}, bytes.Repeat([]byte{0x42}, 12)...)
	route, err := ResolveRoute(device, Intent{
		Operation:  OperationEncrypt,
		Algorithm:  AlgorithmChaCha20,
		CipherMode: CipherModeChaCha20,
		IV:         iv,
	})
	if err != nil {
		t.Fatalf("ResolveRoute: %v", err)
	}
	if route.Mechanism.Mechanism != raw.CKM_CHACHA20 {
		t.Fatalf("mechanism = %#x, want CKM_CHACHA20", route.Mechanism.Mechanism)
	}
	parameters, ok := route.Mechanism.Parameter.(raw.ChaCha20Params)
	if !ok {
		t.Fatalf("parameter type = %T, want raw.ChaCha20Params", route.Mechanism.Parameter)
	}
	if !bytes.Equal(parameters.BlockCounter, []byte{1, 0, 0, 0}) || !bytes.Equal(parameters.Nonce, iv[4:]) {
		t.Fatalf("parameters = %#v", parameters)
	}
}

func TestResolveChaCha20RejectsBadInput(t *testing.T) {
	device := testDevice(adapterDefinition{name: "generic"}, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_CHACHA20_POLY1305): {Flags: raw.CKF_ENCRYPT},
		raw.MechanismType(raw.CKM_CHACHA20):          {Flags: raw.CKF_ENCRYPT},
	})
	if _, err := ResolveRoute(device, Intent{Operation: OperationEncrypt, Algorithm: AlgorithmChaCha20, IV: make([]byte, 8)}); err == nil {
		t.Fatal("expected an error for an 8-byte ChaCha20-Poly1305 nonce")
	}
	if _, err := ResolveRoute(device, Intent{Operation: OperationEncrypt, Algorithm: AlgorithmChaCha20, CipherMode: CipherModeChaCha20, IV: make([]byte, 12)}); err == nil {
		t.Fatal("expected an error for a 12-byte ChaCha20 IV")
	}
	if _, err := ResolveRoute(device, Intent{Operation: OperationEncrypt, Algorithm: AlgorithmChaCha20, IV: make([]byte, 12), TagBits: 64}); err == nil {
		t.Fatal("expected an error for a non-128 ChaCha20-Poly1305 tag")
	}
}
