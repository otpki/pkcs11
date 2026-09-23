package utimaco

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// Module implements all Utimaco-specific behavior behind the root
// pkcs11.VendorModule contract. It is immutable and safe for concurrent use.
type Module struct {
	pkcs11.VendorBase
	quantumProtect bool
}

// Option configures a Utimaco Module.
type Option func(*Module)

// WithQuantumProtect declares that the token runs QuantumProtect firmware.
// QuantumProtect mechanisms are vendor-defined and deliberately absent from
// C_GetMechanismList and C_GetMechanismInfo, so their presence cannot be
// discovered through Cryptoki; the caller must declare it, mirroring the
// legacy proxy's pqc_firmware configuration flag.
func WithQuantumProtect() Option {
	return func(m *Module) { m.quantumProtect = true }
}

// New returns the unified Utimaco integration. It detects CryptoServer,
// u.trust, CP5, and QuantumProtect variants from standard module/token data and
// proprietary mechanism availability.
func New(options ...Option) pkcs11.VendorModule {
	module := &Module{}
	for _, option := range options {
		if option != nil {
			option(module)
		}
	}
	return module
}

// Modules returns the modules supplied by this package. It exists so callers
// can concatenate package-provided module sets uniformly.
func Modules() []pkcs11.VendorModule { return []pkcs11.VendorModule{New()} }

// Definition describes discovery, matching, identifiers, behavior, and the
// conformance contract for the unified Utimaco module.
func (*Module) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID:       ID,
		Name:     "Utimaco CryptoServer",
		Priority: 120,
		Source:   "Utimaco CryptoServer 6.4 and QuantumProtect 1.5 interface definitions",
		MatchFunc: func(fingerprint pkcs11.Fingerprint) pkcs11.VendorMatch {
			return matchUtimaco(fingerprint)
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"UTIMACO_PKCS11_MODULE", "CS_PKCS11_R3_LIB"},
			ModuleNames: map[string][]string{
				"linux":   {"libcs_pkcs11_R3.so", "libcs_pkcs11.so"},
				"darwin":  {"libcs_pkcs11_R3.dylib", "libcs_pkcs11.dylib"},
				"windows": {"cs_pkcs11_R3.dll", "cs_pkcs11.dll"},
			},
			SearchDirectories: map[string][]string{
				"linux":   {"/opt/utimaco/lib", "/usr/local/lib/utimaco"},
				"windows": {`C:\Program Files\Utimaco\CryptoServer\Lib`},
			},
		},
		Catalog:                 quantumProtectCatalog(),
		Behavior:                pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		PreferVendorIdentifiers: false,
		Conformance: pkcs11.VendorConformance{
			Provider: "utimaco-qp",
			Notes:    "Requires the separately supplied licensed Utimaco GP simulator and QuantumProtect evaluation archives (providers utimaco-gp and utimaco-qp)",
		},
	}
}

func matchUtimaco(fingerprint pkcs11.Fingerprint) pkcs11.VendorMatch {
	text := strings.ToLower(strings.Join([]string{
		fingerprint.Module.ManufacturerID,
		fingerprint.Module.LibraryDescription,
		fingerprint.Slot.ManufacturerID,
		fingerprint.Slot.SlotDescription,
		fingerprint.Token.ManufacturerID,
		fingerprint.Token.Model,
		fingerprint.ModulePath,
	}, " "))

	matched := strings.Contains(text, "utimaco") || strings.Contains(text, "cryptoserver") || strings.Contains(text, "cs_pkcs11")
	if !matched {
		return pkcs11.VendorMatch{}
	}

	result := pkcs11.VendorMatch{Matched: true, Score: 350, Name: "Utimaco CryptoServer", Variant: "cryptoserver", Reasons: []string{"Utimaco/CryptoServer fingerprint"}}
	switch {
	case strings.Contains(text, "cp5"):
		result.Name, result.Variant, result.Score = "Utimaco CP5", "cp5", 410
		result.Reasons = append(result.Reasons, "CP5 product fingerprint")
	case strings.Contains(text, "u.trust") || strings.Contains(text, "utrust"):
		result.Name, result.Variant, result.Score = "Utimaco u.trust", "u.trust", 400
		result.Reasons = append(result.Reasons, "u.trust product fingerprint")
	}

	if hasMechanism(fingerprint, MechanismMLDSAKeyPairGen) || hasMechanism(fingerprint, MechanismMLKEMKeyPairGen) || hasMechanism(fingerprint, MechanismHSSKeyGen) {
		result.Name = "Utimaco QuantumProtect"
		result.Variant += "+quantumprotect"
		result.Score += 200
		result.Reasons = append(result.Reasons, "QuantumProtect proprietary mechanism inventory")
	}
	return result
}

func quantumProtectCatalog() pkcs11.VendorCatalog {
	id := func(value uint) pkcs11.NumericID { return pkcs11.NumericID(value) }
	return pkcs11.VendorCatalog{
		Level:  pkcs11.CatalogPublic,
		Source: "Utimaco CryptoServer 6.4 and QuantumProtect 1.5 interface definitions",
		Mechanisms: map[string]pkcs11.NumericID{
			"dilithium-key-pair-gen": id(MechanismDilithiumKeyPairGen),
			"kyber-key-pair-gen":     id(MechanismKyberKeyPairGen),
			"dilithium":              id(MechanismDilithiumSign),
			"dilithium-verify":       id(MechanismDilithiumVerify),
			"kyber":                  id(MechanismKyberEncapsulate),
			"kyber-encapsulate":      id(MechanismKyberEncapsulate),
			"kyber-decapsulate":      id(MechanismKyberDecapsulate),

			"ml-dsa-key-pair-gen":       id(MechanismMLDSAKeyPairGen),
			"ml-kem-key-pair-gen":       id(MechanismMLKEMKeyPairGen),
			"ml-dsa":                    id(MechanismMLDSASign),
			"ml-dsa-verify":             id(MechanismMLDSAVerify),
			"hash-ml-dsa":               id(MechanismMLDSASign),
			"hash-ml-dsa-verify":        id(MechanismMLDSAVerify),
			"ml-dsa-external-mu":        id(MechanismMLDSAExternalMuSign),
			"ml-dsa-external-mu-verify": id(MechanismMLDSAExternalMuVerify),
			"ml-kem-encapsulate":        id(MechanismMLKEMEncapsulate),
			"ml-kem-decapsulate":        id(MechanismMLKEMDecapsulate),

			"utimaco-ml-dsa-wrap-aes-kwp":      id(MechanismMLDSAWrapAESKWP),
			"utimaco-ml-dsa-unwrap-aes-kwp":    id(MechanismMLDSAUnwrapAESKWP),
			"utimaco-ml-dsa-export-public-key": id(MechanismMLDSAExportPublicKey),
			"utimaco-ml-kem-export-public-key": id(MechanismMLKEMExportPublicKey),
			"utimaco-ml-dsa-shake256":          id(MechanismMLDSASHAKE256),

			"hss-key-pair-gen":    id(MechanismHSSKeyGen),
			"lms-key-pair-gen":    id(MechanismLMSKeyGen),
			"xmss-key-pair-gen":   id(MechanismXMSSKeyGen),
			"xmssmt-key-pair-gen": id(MechanismXMSSKeyGen),
			"hss":                 id(MechanismHSSSign),
			"hss-verify":          id(MechanismHSSVerify),
			"lms":                 id(MechanismLMSSign),
			"lms-verify":          id(MechanismLMSVerify),
			"xmss":                id(MechanismXMSSSign),
			"xmss-verify":         id(MechanismXMSSVerify),
			"xmssmt":              id(MechanismXMSSSign),
			"xmssmt-verify":       id(MechanismXMSSVerify),
		},
		KeyTypes: map[string]pkcs11.NumericID{
			"dilithium": id(KeyTypeDilithium),
			"kyber":     id(KeyTypeKyber),
			"ml-dsa":    id(KeyTypeMLDSA),
			"ml-kem":    id(KeyTypeMLKEM),
		},
		Attributes: map[string]pkcs11.NumericID{
			"utimaco-custom-data": id(AttributeCustomData),
		},
		ParameterSets: map[string]pkcs11.NumericID{
			"ml-dsa-44":   id(uint(ParameterSet44Or512)),
			"ml-dsa-65":   id(uint(ParameterSet65Or768)),
			"ml-dsa-87":   id(uint(ParameterSet87Or1024)),
			"ml-kem-512":  id(uint(ParameterSet44Or512)),
			"ml-kem-768":  id(uint(ParameterSet65Or768)),
			"ml-kem-1024": id(uint(ParameterSet87Or1024)),
		},
	}
}

func hasMechanism(fingerprint pkcs11.Fingerprint, mechanism uint) bool {
	_, ok := fingerprint.Mechanisms[raw.MechanismType(mechanism)]
	return ok
}

// quantumProtectMechanisms synthesises the C_GetMechanismInfo answers
// QuantumProtect firmware never returns for its vendor-defined mechanisms.
// Key-size bounds use the algorithm public-key byte ranges (FIPS 203/204).
func quantumProtectMechanisms() map[uint]raw.MechanismInfo {
	const (
		mldsaMinPublicKeyBytes uint = 1312
		mldsaMaxPublicKeyBytes uint = 2592
		mlkemMinPublicKeyBytes uint = 800
		mlkemMaxPublicKeyBytes uint = 1568
	)
	signVerify := raw.MechanismInfo{MinKeySize: mldsaMinPublicKeyBytes, MaxKeySize: mldsaMaxPublicKeyBytes, Flags: raw.CKF_SIGN | raw.CKF_VERIFY}
	return map[uint]raw.MechanismInfo{
		MechanismDilithiumKeyPairGen: {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismKyberKeyPairGen:     {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismDilithiumSign:       {Flags: raw.CKF_SIGN},
		MechanismDilithiumVerify:     {Flags: raw.CKF_VERIFY},
		MechanismKyberEncapsulate:    {Flags: raw.CKF_DERIVE},
		MechanismKyberDecapsulate:    {Flags: raw.CKF_DERIVE},

		MechanismMLDSAKeyPairGen:       {MinKeySize: mldsaMinPublicKeyBytes, MaxKeySize: mldsaMaxPublicKeyBytes, Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismMLKEMKeyPairGen:       {MinKeySize: mlkemMinPublicKeyBytes, MaxKeySize: mlkemMaxPublicKeyBytes, Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismMLDSASign:             signVerify,
		MechanismMLDSAExternalMuSign:   {MinKeySize: mldsaMinPublicKeyBytes, MaxKeySize: mldsaMaxPublicKeyBytes, Flags: raw.CKF_SIGN},
		MechanismMLDSAVerify:           signVerify,
		MechanismMLDSAExternalMuVerify: {MinKeySize: mldsaMinPublicKeyBytes, MaxKeySize: mldsaMaxPublicKeyBytes, Flags: raw.CKF_VERIFY},
		MechanismMLDSAWrapAESKWP:       {Flags: raw.CKF_WRAP},
		MechanismMLDSAUnwrapAESKWP:     {Flags: raw.CKF_UNWRAP},
		MechanismMLKEMEncapsulate:      {MinKeySize: mlkemMinPublicKeyBytes, MaxKeySize: mlkemMaxPublicKeyBytes, Flags: raw.CKF_DERIVE},
		MechanismMLKEMDecapsulate:      {MinKeySize: mlkemMinPublicKeyBytes, MaxKeySize: mlkemMaxPublicKeyBytes, Flags: raw.CKF_DERIVE},
		MechanismMLDSAExportPublicKey:  {Flags: raw.CKF_DERIVE},
		MechanismMLKEMExportPublicKey:  {Flags: raw.CKF_DERIVE},
		MechanismMLDSASHAKE256:         {Flags: raw.CKF_DIGEST},

		MechanismHSSKeyGen:        {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismHSSKeyGenSeed:    {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismXMSSKeyGen:       {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismXMSSKeyGenSeed:   {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismLMSKeyGen:        {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismLMSKeyGenSeed:    {Flags: raw.CKF_GENERATE_KEY_PAIR},
		MechanismHSSGetPublicKey:  {Flags: raw.CKF_DERIVE},
		MechanismXMSSGetPublicKey: {Flags: raw.CKF_DERIVE},
		MechanismLMSGetPublicKey:  {Flags: raw.CKF_DERIVE},
		MechanismHSSSign:          {Flags: raw.CKF_SIGN},
		MechanismXMSSSign:         {Flags: raw.CKF_SIGN},
		MechanismLMSSign:          {Flags: raw.CKF_SIGN},
		MechanismHSSVerify:        {Flags: raw.CKF_VERIFY},
		MechanismXMSSVerify:       {Flags: raw.CKF_VERIFY},
		MechanismLMSVerify:        {Flags: raw.CKF_VERIFY},
	}
}

func routeUsesVendor(route pkcs11.Route) bool {
	return strings.HasPrefix(route.MechanismSource, "vendor-adapter") || route.Mechanism == nil
}

type routeKind uint8

const (
	routeKindML routeKind = iota + 1
	routeKindDeriveKEM
	routeKindHBS
)

type routeData struct {
	Kind routeKind
	Set  ParameterSet
}

// AdaptRoute keeps advertised standard PKCS #11 3.2 mechanisms unchanged and
// fills only the documented QuantumProtect fallback contracts.
func (*Module) AdaptRoute(device pkcs11.Device, route pkcs11.Route) (pkcs11.Route, error) {
	if !routeUsesVendor(route) {
		return route, nil
	}

	if isHBSAlgorithm(route.Intent.Algorithm) {
		mechanism, err := hbsMechanism(route.Intent)
		if err != nil {
			return route, err
		}
		if !device.Capabilities.HasMechanism(mechanism) {
			return route, fmt.Errorf("utimaco: token does not expose QuantumProtect mechanism 0x%x for %s %s", mechanism, route.Intent.Operation, route.Intent.Algorithm)
		}
		route.Mechanism = raw.NewMechanism(mechanism, route.Intent.MechanismParameter)
		route.MechanismSource = "vendor-adapter"
		route.KeyType = raw.CKK_GENERIC_SECRET
		route.ParameterSet = 0
		route.OmitParameterSetAttribute = true
		route.Execution.ReadWrite = true
		if route.Intent.Operation == pkcs11.OperationSign {
			route.Execution.Replay = pkcs11.RouteReplayNever
		}
		route.VendorData = routeData{Kind: routeKindHBS}
		route.Reasons = append(route.Reasons, "QuantumProtect maps the logical HBS key pair to one resident secret object")
		return route, nil
	}

	set, err := parameterSet(route.Intent.Algorithm)
	if err != nil {
		return route, nil
	}

	mechanism, err := mlMechanism(route.Intent)
	if err != nil {
		return route, err
	}
	if route.Mechanism != nil && strings.HasPrefix(route.MechanismSource, "vendor-adapter") {
		mechanism = route.Mechanism.Mechanism
	}
	if !device.Capabilities.HasMechanism(mechanism) {
		return route, fmt.Errorf("utimaco: token does not expose QuantumProtect mechanism 0x%x for %s %s", mechanism, route.Intent.Operation, route.Intent.Algorithm)
	}

	route.Mechanism = raw.NewMechanism(mechanism, nil)
	route.MechanismSource = "vendor-adapter"
	route.ParameterSet = uint(set)
	route.OmitParameterSetAttribute = true
	route.VendorData = routeData{Kind: routeKindML, Set: set}
	if isMLDSA(route.Intent.Algorithm) {
		route.KeyType = KeyTypeMLDSA
	} else {
		route.KeyType = KeyTypeMLKEM
	}

	switch route.Intent.Operation {
	case pkcs11.OperationGenerate:
		parameter := route.Intent.MechanismParameter
		if parameter == nil {
			parameter, err = (GenerateParameters{Flags: 1, Set: set}).MarshalBinary()
		}
		if err != nil {
			return route, err
		}
		route.Mechanism.Parameter = parameter
		route.Reasons = append(route.Reasons, "QuantumProtect u4u4v2* key-generation parameters")
	case pkcs11.OperationSign, pkcs11.OperationVerify:
		if len(route.Intent.Context) != 0 {
			return route, fmt.Errorf("utimaco: direct QuantumProtect ML-DSA does not expose a context field; use a precomputed external mu")
		}
		if route.Intent.Hedge != pkcs11.HedgePreferred {
			return route, fmt.Errorf("utimaco: QuantumProtect ML-DSA does not expose hedge mode %d", route.Intent.Hedge)
		}
		if route.Intent.Hash != 0 && !route.Intent.Prehashed && !route.Intent.ExternalMu {
			return route, fmt.Errorf("utimaco: QuantumProtect has no combined %s-and-ML-DSA mechanism; pass the digest with prehash mode", route.Intent.Hash)
		}
		flags := uint32(0)
		if route.Intent.Prehashed {
			if route.Intent.Hash == 0 {
				return route, fmt.Errorf("utimaco: ML-DSA prehash mode requires an explicit hash")
			}
			flags = MLDSAFlagPreHash
		}
		parameter := route.Intent.MechanismParameter
		if parameter == nil {
			parameter, err = (SignatureParameters{Flags: flags, Set: set}).MarshalBinary()
		}
		if err != nil {
			return route, err
		}
		route.Mechanism.Parameter = parameter
		route.Reasons = append(route.Reasons, "QuantumProtect flags/parameter-set signature record")
	case pkcs11.OperationEncapsulate, pkcs11.OperationDecapsulate:
		route.Execution.ReadWrite = true
		route.Execution.Replay = pkcs11.RouteReplayNever
		route.VendorData = routeData{Kind: routeKindDeriveKEM, Set: set}
		// Public key or ciphertext bytes are known only when the operation hook
		// resolves the caller's object. The hook completes the parameter record.
		route.Mechanism.Parameter = nil
	}
	return route, nil
}

func parameterSet(algorithm pkcs11.Algorithm) (ParameterSet, error) {
	switch algorithm {
	case pkcs11.AlgorithmMLDSA44, pkcs11.AlgorithmMLKEM512:
		return ParameterSet44Or512, nil
	case pkcs11.AlgorithmMLDSA65, pkcs11.AlgorithmMLKEM768:
		return ParameterSet65Or768, nil
	case pkcs11.AlgorithmMLDSA87, pkcs11.AlgorithmMLKEM1024:
		return ParameterSet87Or1024, nil
	default:
		return 0, fmt.Errorf("utimaco: no QuantumProtect parameter-set mapping for %s", algorithm)
	}
}

func isMLDSA(algorithm pkcs11.Algorithm) bool {
	switch algorithm {
	case pkcs11.AlgorithmMLDSA44, pkcs11.AlgorithmMLDSA65, pkcs11.AlgorithmMLDSA87:
		return true
	default:
		return false
	}
}

func isMLKEM(algorithm pkcs11.Algorithm) bool {
	switch algorithm {
	case pkcs11.AlgorithmMLKEM512, pkcs11.AlgorithmMLKEM768, pkcs11.AlgorithmMLKEM1024:
		return true
	default:
		return false
	}
}

func isHBSAlgorithm(algorithm pkcs11.Algorithm) bool {
	switch algorithm {
	case pkcs11.AlgorithmHSS, pkcs11.AlgorithmLMS, pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
		return true
	default:
		return false
	}
}

func mlMechanism(intent pkcs11.Intent) (uint, error) {
	switch intent.Operation {
	case pkcs11.OperationGenerate:
		if isMLDSA(intent.Algorithm) {
			return MechanismMLDSAKeyPairGen, nil
		}
		if isMLKEM(intent.Algorithm) {
			return MechanismMLKEMKeyPairGen, nil
		}
	case pkcs11.OperationSign:
		if intent.ExternalMu {
			return MechanismMLDSAExternalMuSign, nil
		}
		return MechanismMLDSASign, nil
	case pkcs11.OperationVerify:
		if intent.ExternalMu {
			return MechanismMLDSAExternalMuVerify, nil
		}
		return MechanismMLDSAVerify, nil
	case pkcs11.OperationEncapsulate:
		return MechanismMLKEMEncapsulate, nil
	case pkcs11.OperationDecapsulate:
		return MechanismMLKEMDecapsulate, nil
	}
	return 0, fmt.Errorf("utimaco: unsupported QuantumProtect route %s %s", intent.Operation, intent.Algorithm)
}

func hbsMechanism(intent pkcs11.Intent) (uint, error) {
	switch intent.Operation {
	case pkcs11.OperationGenerate:
		switch intent.Algorithm {
		case pkcs11.AlgorithmHSS:
			return MechanismHSSKeyGen, nil
		case pkcs11.AlgorithmLMS:
			return MechanismLMSKeyGen, nil
		case pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
			return MechanismXMSSKeyGen, nil
		}
	case pkcs11.OperationSign:
		switch intent.Algorithm {
		case pkcs11.AlgorithmHSS:
			return MechanismHSSSign, nil
		case pkcs11.AlgorithmLMS:
			return MechanismLMSSign, nil
		case pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
			return MechanismXMSSSign, nil
		}
	case pkcs11.OperationVerify:
		switch intent.Algorithm {
		case pkcs11.AlgorithmHSS:
			return MechanismHSSVerify, nil
		case pkcs11.AlgorithmLMS:
			return MechanismLMSVerify, nil
		case pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
			return MechanismXMSSVerify, nil
		}
	}
	return 0, fmt.Errorf("utimaco: unsupported HBS route %s %s", intent.Operation, intent.Algorithm)
}

// NormalizeTemplate translates standard 3.2 object attributes to the Utimaco
// object contract immediately before the raw call.
//
// The CryptoServer PKCS #11 client library validates every template against a
// built-in attribute-rule table before anything reaches the device. Attributes
// without a rule are rejected client-side with CKR_TEMPLATE_INCONSISTENT:
//
//   - CKA_COPYABLE and CKA_DESTROYABLE have no rules at all; the firmware
//     predates the PKCS #11 v2.40 object-copy/destroy model. Their absence
//     keeps the Cryptoki defaults (keys remain copyable and destroyable by
//     holders with adequate rights), which matches what the library can
//     express.
//   - CKA_ALWAYS_AUTHENTICATE has rules only for a subset of private-key
//     types; the generated keys never enable always-authenticate semantics, so
//     dropping it preserves the requested policy.
//   - CKA_PUBLIC_KEY_INFO has no rule for certificate objects; the client
//     library rejects certificate imports that carry it even though the
//     certificate DER already encodes the subject public key.
//
// QuantumProtect additionally carries the ML parameter set in its binary
// mechanism record, predates C_EncapsulateKey/C_DecapsulateKey, and has no
// CKA_ENCAPSULATE/CKA_DECAPSULATE attribute rules: KEM usage is expressed with
// CKA_DERIVE because encapsulation and decapsulation run through C_DeriveKey.
func (m *Module) NormalizeTemplate(_ pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := pkcs11.RemoveAttributes(attributes, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE, raw.CKA_ALWAYS_AUTHENTICATE, raw.CKA_PUBLIC_KEY_INFO)
	if m.quantumProtect {
		hasDerive := false
		rewritten := make([]*raw.Attribute, 0, len(result))
		for _, attribute := range result {
			switch attribute.Type {
			case raw.CKA_ENCAPSULATE, raw.CKA_DECAPSULATE:
				if hasDerive {
					continue
				}
				hasDerive = true
				attribute = raw.NewAttribute(raw.CKA_DERIVE, attribute.Value)
			case raw.CKA_DERIVE:
				hasDerive = true
			}
			rewritten = append(rewritten, attribute)
		}
		result = rewritten
	}
	class, _ := pkcs11.AttributeULong(result, raw.CKA_CLASS)
	keyType, _ := pkcs11.AttributeULong(result, raw.CKA_KEY_TYPE)
	if keyType != KeyTypeMLDSA && keyType != KeyTypeMLKEM {
		return result, nil
	}

	// QuantumProtect carries the ML parameter set in its binary mechanism record.
	result = pkcs11.RemoveAttributes(result, raw.CKA_PARAMETER_SET)
	if keyType == KeyTypeMLKEM {
		// Its KEM operations predate C_EncapsulateKey/C_DecapsulateKey and are
		// exposed through C_DeriveKey.
		result = pkcs11.RemoveAttributes(result, raw.CKA_ENCAPSULATE, raw.CKA_DECAPSULATE)
		if class == raw.CKO_PUBLIC_KEY || class == raw.CKO_PRIVATE_KEY {
			result = pkcs11.MergeAttributes(result, []*raw.Attribute{raw.NewAttribute(raw.CKA_DERIVE, true)})
		}
	} else if class == raw.CKO_PRIVATE_KEY {
		// The vendor generation sample requires CKA_DERIVE in addition to CKA_SIGN.
		result = pkcs11.MergeAttributes(result, []*raw.Attribute{raw.NewAttribute(raw.CKA_DERIVE, true)})
	}
	return result, nil
}

// ObjectAttributes requests the proprietary public-data attribute during
// discovery and key loading.
func (*Module) ObjectAttributes() []uint { return []uint{AttributeCustomData} }

// InferAlgorithm uses QuantumProtect key types and standardized public-key
// lengths to recover the root algorithm from located objects.
func (*Module) InferAlgorithm(metadata pkcs11.VendorObjectMetadata) (pkcs11.Algorithm, bool) {
	value := attributeBytes(metadata.Attributes, AttributeCustomData)
	switch metadata.KeyType {
	case KeyTypeMLDSA:
		switch len(value) {
		case 1312:
			return pkcs11.AlgorithmMLDSA44, true
		case 1952:
			return pkcs11.AlgorithmMLDSA65, true
		case 2592:
			return pkcs11.AlgorithmMLDSA87, true
		}
	case KeyTypeMLKEM:
		switch len(value) {
		case 800:
			return pkcs11.AlgorithmMLKEM512, true
		case 1184:
			return pkcs11.AlgorithmMLKEM768, true
		case 1568:
			return pkcs11.AlgorithmMLKEM1024, true
		}
	}
	return "", false
}

// KeyPairModel exposes QuantumProtect's one-object HSS/LMS/XMSS representation
// through the root API's logical KeyPair type.
func (*Module) KeyPairModel(algorithm pkcs11.Algorithm, route pkcs11.Route) (pkcs11.VendorKeyPairModel, bool) {
	data, _ := route.VendorData.(routeData)
	if !isHBSAlgorithm(algorithm) || (route.VendorData != nil && data.Kind != routeKindHBS) {
		return pkcs11.VendorKeyPairModel{}, false
	}
	return pkcs11.VendorKeyPairModel{SingleObject: true, ObjectClass: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET}, true
}

// GenerateKeyPair handles only QuantumProtect's nonstandard stateful HBS object
// model. ML-DSA and ML-KEM use the generic C_GenerateKeyPair path.
func (*Module) GenerateKeyPair(ctx context.Context, session pkcs11.VendorSession, route pkcs11.Route, options pkcs11.KeyPairOptions) (pkcs11.KeyPair, bool, error) {
	data, _ := route.VendorData.(routeData)
	if data.Kind != routeKindHBS {
		return pkcs11.KeyPair{}, false, nil
	}

	parameter, err := hbsGenerationParameter(options)
	if err != nil {
		return pkcs11.KeyPair{}, true, err
	}
	mechanism := raw.NewMechanism(route.Mechanism.Mechanism, parameter)
	attributes, err := hbsKeyTemplate(options)
	if err != nil {
		return pkcs11.KeyPair{}, true, err
	}

	var handle raw.ObjectHandle
	err = session.Call(ctx, "utimaco-hbs-generate-key", func(module raw.Module, nativeSession raw.SessionHandle) error {
		var callErr error
		handle, callErr = module.GenerateKey(nativeSession, []*raw.Mechanism{mechanism}, attributes)
		return callErr
	})
	if err != nil {
		return pkcs11.KeyPair{}, true, err
	}
	session.InvalidateObjects()
	object := pkcs11.ObjectRef{
		Handle: handle, Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET,
		Algorithm: options.Algorithm, Label: options.Label, ID: append([]byte(nil), options.ID...),
	}
	return pkcs11.KeyPair{Public: object, Private: object}, true, nil
}

func hbsGenerationParameter(options pkcs11.KeyPairOptions) ([]byte, error) {
	if options.MechanismParameter != nil {
		value, ok := options.MechanismParameter.([]byte)
		if !ok {
			return nil, fmt.Errorf("utimaco: HBS mechanism parameter must be []byte, got %T", options.MechanismParameter)
		}
		return append([]byte(nil), value...), nil
	}

	switch options.Algorithm {
	case pkcs11.AlgorithmHSS, pkcs11.AlgorithmLMS:
		parameters := options.HSS
		if parameters == nil && options.Algorithm == pkcs11.AlgorithmLMS {
			parameters = &pkcs11.HSSParameters{Levels: 1, LMSTypes: []uint{6}, LMOTSTypes: []uint{3}}
		}
		if parameters == nil {
			return nil, fmt.Errorf("utimaco: HSS generation requires hierarchy parameters")
		}
		levels := parameters.Levels
		if levels == 0 {
			levels = uint(len(parameters.LMSTypes))
		}
		if levels == 0 || levels > 8 || len(parameters.LMSTypes) != int(levels) || len(parameters.LMOTSTypes) != int(levels) {
			return nil, fmt.Errorf("utimaco: HSS levels must match one to eight LMS and LM-OTS selectors")
		}
		if options.Algorithm == pkcs11.AlgorithmLMS && levels != 1 {
			return nil, fmt.Errorf("utimaco: LMS requires exactly one level")
		}
		lms, err := byteSelectors(parameters.LMSTypes, "LMS")
		if err != nil {
			return nil, err
		}
		lmots, err := byteSelectors(parameters.LMOTSTypes, "LM-OTS")
		if err != nil {
			return nil, err
		}
		return (HSSGenerateParameters{RandomSource: HBSRandomPseudo, LMSTypes: lms, LMOTSTypes: lmots, AuxSize: 10916}).MarshalBinary()
	case pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
		if options.ParameterSet == 0 || options.ParameterSet > 0xff {
			return nil, fmt.Errorf("utimaco: %s generation requires a one-byte OID selector in ParameterSet", options.Algorithm)
		}
		return (XMSSGenerateParameters{RandomSource: HBSRandomPseudo, MultiTree: options.Algorithm == pkcs11.AlgorithmXMSSMT, OID: byte(options.ParameterSet), AuxSize: 8196}).MarshalBinary()
	default:
		return nil, fmt.Errorf("utimaco: %s is not a QuantumProtect HBS algorithm", options.Algorithm)
	}
}

func byteSelectors(values []uint, name string) ([]byte, error) {
	result := make([]byte, len(values))
	for index, value := range values {
		if value > 0xff {
			return nil, fmt.Errorf("utimaco: %s selector %d exceeds one byte", name, value)
		}
		result[index] = byte(value)
	}
	return result, nil
}

func hbsKeyTemplate(options pkcs11.KeyPairOptions) ([]*raw.Attribute, error) {
	policy := pkcs11.DefaultPrivateKeyPolicy()
	if options.PrivatePolicy != nil {
		policy = *options.PrivatePolicy
	}
	if !policy.Sensitive || policy.Extractable {
		return nil, fmt.Errorf("utimaco: stateful signature keys must be sensitive and non-extractable")
	}
	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
		raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
		raw.NewAttribute(raw.CKA_TOKEN, policy.Token),
		raw.NewAttribute(raw.CKA_PRIVATE, policy.Private),
		raw.NewAttribute(raw.CKA_SENSITIVE, policy.Sensitive),
		raw.NewAttribute(raw.CKA_EXTRACTABLE, policy.Extractable),
		raw.NewAttribute(raw.CKA_MODIFIABLE, policy.Modifiable),
		// CKA_COPYABLE and CKA_DESTROYABLE are omitted: the QuantumProtect
		// client library has no attribute rules for them.
		raw.NewAttribute(raw.CKA_DERIVE, true),
		raw.NewAttribute(raw.CKA_VALUE_LEN, uint(32)),
	}
	if options.Label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, options.Label))
	}
	if options.ID != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, options.ID))
	}
	if options.TemplatePolicy != nil {
		var err error
		attributes, err = options.TemplatePolicy.ApplyTemplate(pkcs11.TemplateContext{
			Operation: pkcs11.OperationGenerate, Algorithm: options.Algorithm,
			ObjectClass: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET,
			Label: options.Label, ID: append([]byte(nil), options.ID...),
		}, pkcs11.CloneAttributes(attributes))
		if err != nil {
			return nil, err
		}
	}
	attributes = pkcs11.MergeAttributes(attributes, options.PublicAttributes, options.PrivateAttributes)
	class, classOK := pkcs11.AttributeULong(attributes, raw.CKA_CLASS)
	keyType, keyTypeOK := pkcs11.AttributeULong(attributes, raw.CKA_KEY_TYPE)
	if !classOK || class != raw.CKO_SECRET_KEY || !keyTypeOK || keyType != raw.CKK_GENERIC_SECRET {
		return nil, fmt.Errorf("utimaco: HBS template cannot override CKA_CLASS or CKA_KEY_TYPE")
	}
	return attributes, nil
}

// LoadPublicKey reads QuantumProtect public data. HBS keys require derivation of
// a temporary verification carrier; ML-DSA and ML-KEM normally expose the bytes
// through CKA_UTI_CUSTOM_DATA on the private object.
func (*Module) LoadPublicKey(ctx context.Context, session pkcs11.VendorSession, object pkcs11.ObjectRef, algorithm pkcs11.Algorithm) (crypto.PublicKey, bool, error) {
	if isHBSAlgorithm(algorithm) {
		var encoding []byte
		err := withHBSPublicObject(ctx, session, object, algorithm, func(module raw.Module, nativeSession raw.SessionHandle, temporary raw.ObjectHandle) error {
			var readErr error
			encoding, readErr = readCustomData(module, nativeSession, temporary)
			return readErr
		})
		if err != nil {
			return nil, true, err
		}
		return pkcs11.OpaquePublicKey{Algorithm: algorithm, Encoding: encoding}, true, nil
	}
	if !isMLDSA(algorithm) && !isMLKEM(algorithm) {
		return nil, false, nil
	}
	encoding, err := customDataForObject(ctx, session, object)
	if err != nil {
		return nil, true, err
	}
	return pkcs11.OpaquePublicKey{Algorithm: algorithm, Encoding: encoding}, true, nil
}

// Verify handles HBS verification through a temporary derived public carrier.
// All other Utimaco signatures use the generic managed PKCS #11 path.
func (*Module) Verify(ctx context.Context, session pkcs11.VendorSession, object pkcs11.ObjectRef, route pkcs11.Route, data, signature []byte) (bool, error) {
	routeInfo, _ := route.VendorData.(routeData)
	if routeInfo.Kind != routeKindHBS {
		return false, nil
	}
	err := withHBSPublicObject(ctx, session, object, route.Intent.Algorithm, func(module raw.Module, nativeSession raw.SessionHandle, temporary raw.ObjectHandle) error {
		if err := module.VerifyInit(nativeSession, []*raw.Mechanism{route.Mechanism}, temporary); err != nil {
			return err
		}
		return module.Verify(nativeSession, data, signature)
	})
	return true, err
}

func withHBSPublicObject(ctx context.Context, session pkcs11.VendorSession, object pkcs11.ObjectRef, algorithm pkcs11.Algorithm, fn func(raw.Module, raw.SessionHandle, raw.ObjectHandle) error) error {
	base, err := session.Resolve(object)
	if err != nil {
		return err
	}
	mechanism, err := hbsPublicMechanism(algorithm)
	if err != nil {
		return err
	}
	return session.Call(ctx, "utimaco-hbs-public-object", func(module raw.Module, nativeSession raw.SessionHandle) (operationErr error) {
		temporary, err := module.DeriveKey(nativeSession,
			[]*raw.Mechanism{raw.NewMechanism(mechanism, nil)}, base,
			[]*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
				raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
				raw.NewAttribute(raw.CKA_TOKEN, false),
				raw.NewAttribute(raw.CKA_VALUE_LEN, uint(32)),
			},
		)
		if err != nil {
			return err
		}
		defer func() { operationErr = errors.Join(operationErr, module.DestroyObject(nativeSession, temporary)) }()
		return fn(module, nativeSession, temporary)
	})
}

func hbsPublicMechanism(algorithm pkcs11.Algorithm) (uint, error) {
	switch algorithm {
	case pkcs11.AlgorithmHSS:
		return MechanismHSSGetPublicKey, nil
	case pkcs11.AlgorithmLMS:
		return MechanismLMSGetPublicKey, nil
	case pkcs11.AlgorithmXMSS, pkcs11.AlgorithmXMSSMT:
		return MechanismXMSSGetPublicKey, nil
	default:
		return 0, fmt.Errorf("utimaco: %s is not an HBS algorithm", algorithm)
	}
}

// Encapsulate implements QuantumProtect's C_DeriveKey-based ML-KEM contract.
func (m *Module) Encapsulate(ctx context.Context, session pkcs11.VendorSession, publicKey pkcs11.ObjectRef, route pkcs11.Route, options pkcs11.KEMOptions, template []*raw.Attribute) (pkcs11.KEMResult, bool, error) {
	data, _ := route.VendorData.(routeData)
	if data.Kind != routeKindDeriveKEM {
		return pkcs11.KEMResult{}, false, nil
	}
	// The vendor DeriveKey call path bypasses the generic normalization pass, so
	// the derived-secret template must be normalized here.
	template, err := m.NormalizeTemplate(pkcs11.VendorTemplateContext{Operation: "C_DeriveKey"}, template)
	if err != nil {
		return pkcs11.KEMResult{}, true, err
	}
	publicBytes, err := customDataForObject(ctx, session, publicKey)
	if err != nil {
		return pkcs11.KEMResult{}, true, err
	}
	parameter := options.MechanismParameter
	if parameter == nil {
		parameter, err = (EncapsulationParameters{Set: data.Set, PublicKey: publicBytes}).MarshalBinary()
		if err != nil {
			return pkcs11.KEMResult{}, true, err
		}
	}

	var ciphertext []byte
	var secret raw.ObjectHandle
	err = session.Call(ctx, "utimaco-ml-kem-encapsulate", func(module raw.Module, nativeSession raw.SessionHandle) (operationErr error) {
		generationParameter, err := (GenerateParameters{Flags: 1, Set: data.Set}).MarshalBinary()
		if err != nil {
			return err
		}
		publicHandle, privateHandle, err := module.GenerateKeyPair(nativeSession,
			[]*raw.Mechanism{raw.NewMechanism(MechanismMLKEMKeyPairGen, generationParameter)},
			[]*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY),
				raw.NewAttribute(raw.CKA_KEY_TYPE, KeyTypeMLKEM),
				raw.NewAttribute(raw.CKA_TOKEN, false),
				raw.NewAttribute(raw.CKA_DERIVE, true),
			},
			[]*raw.Attribute{
				raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY),
				raw.NewAttribute(raw.CKA_KEY_TYPE, KeyTypeMLKEM),
				raw.NewAttribute(raw.CKA_TOKEN, false),
				raw.NewAttribute(raw.CKA_PRIVATE, true),
				// The firmware refuses to derive a secret less protected than
				// the base key ("property is protected"). The ephemeral key
				// lives only for this call, so it is generated maximally
				// permissive and the caller's secret template decides the
				// derived object's actual policy.
				raw.NewAttribute(raw.CKA_SENSITIVE, false),
				raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
				raw.NewAttribute(raw.CKA_DERIVE, true),
			},
		)
		if err != nil {
			return err
		}
		defer func() {
			operationErr = errors.Join(operationErr,
				ignoreMissingObject(module.DestroyObject(nativeSession, privateHandle)),
				ignoreMissingObject(module.DestroyObject(nativeSession, publicHandle)),
			)
		}()

		secret, err = module.DeriveKey(nativeSession,
			[]*raw.Mechanism{raw.NewMechanism(MechanismMLKEMEncapsulate, parameter)},
			privateHandle, template,
		)
		if err != nil {
			return err
		}
		ciphertext, err = readCustomData(module, nativeSession, secret)
		if err != nil {
			_ = module.DestroyObject(nativeSession, secret)
			secret = 0
			return fmt.Errorf("utimaco: read ML-KEM ciphertext: %w", err)
		}
		return nil
	})
	if err != nil {
		return pkcs11.KEMResult{}, true, err
	}
	session.InvalidateObjects()
	return pkcs11.KEMResult{
		Ciphertext: ciphertext,
		Secret: pkcs11.ObjectRef{
			Handle: secret, Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET,
			Label: options.Label, ID: append([]byte(nil), options.ID...),
		},
	}, true, nil
}

// Decapsulate implements QuantumProtect's C_DeriveKey-based ML-KEM contract.
func (m *Module) Decapsulate(ctx context.Context, session pkcs11.VendorSession, privateKey pkcs11.ObjectRef, ciphertext []byte, route pkcs11.Route, options pkcs11.KEMOptions, template []*raw.Attribute) (pkcs11.ObjectRef, bool, error) {
	data, _ := route.VendorData.(routeData)
	if data.Kind != routeKindDeriveKEM {
		return pkcs11.ObjectRef{}, false, nil
	}
	template, err := m.NormalizeTemplate(pkcs11.VendorTemplateContext{Operation: "C_DeriveKey"}, template)
	if err != nil {
		return pkcs11.ObjectRef{}, true, err
	}
	baseKey, err := session.Resolve(privateKey)
	if err != nil {
		return pkcs11.ObjectRef{}, true, err
	}
	parameter := options.MechanismParameter
	if parameter == nil {
		parameter, err = (DecapsulationParameters{Set: data.Set, Ciphertext: ciphertext}).MarshalBinary()
		if err != nil {
			return pkcs11.ObjectRef{}, true, err
		}
	}
	var secret raw.ObjectHandle
	err = session.Call(ctx, "utimaco-ml-kem-decapsulate", func(module raw.Module, nativeSession raw.SessionHandle) error {
		var callErr error
		secret, callErr = module.DeriveKey(nativeSession,
			[]*raw.Mechanism{raw.NewMechanism(MechanismMLKEMDecapsulate, parameter)},
			baseKey, template,
		)
		return callErr
	})
	if err != nil {
		return pkcs11.ObjectRef{}, true, err
	}
	session.InvalidateObjects()
	return pkcs11.ObjectRef{
		Handle: secret, Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET,
		Label: options.Label, ID: append([]byte(nil), options.ID...),
	}, true, nil
}

func customDataForObject(ctx context.Context, session pkcs11.VendorSession, object pkcs11.ObjectRef) ([]byte, error) {
	value, err := customData(ctx, session, object)
	if err == nil && len(value) != 0 {
		return value, nil
	}
	if object.ID == nil && object.Label == "" && object.UniqueID == "" {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("utimaco: public-data lookup requires a durable object locator")
	}
	private := object
	private.Handle = 0
	private.Class = raw.CKO_PRIVATE_KEY
	value, privateErr := customData(ctx, session, private)
	if privateErr != nil {
		return nil, errors.Join(err, privateErr)
	}
	return value, nil
}

func customData(ctx context.Context, session pkcs11.VendorSession, object pkcs11.ObjectRef) ([]byte, error) {
	handle, err := session.Resolve(object)
	if err != nil {
		return nil, err
	}
	var value []byte
	err = session.Call(ctx, "utimaco-read-custom-data", func(module raw.Module, nativeSession raw.SessionHandle) error {
		var readErr error
		value, readErr = readCustomData(module, nativeSession, handle)
		return readErr
	})
	return value, err
}

func readCustomData(module raw.Module, session raw.SessionHandle, object raw.ObjectHandle) ([]byte, error) {
	attributes, err := module.GetAttributeValue(session, object, []*raw.Attribute{raw.NewAttribute(AttributeCustomData, nil)})
	if len(attributes) == 1 && attributes[0] != nil && len(attributes[0].Value) != 0 {
		return append([]byte(nil), attributes[0].Value...), err
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("utimaco: CKA_UTI_CUSTOM_DATA is unavailable")
}

func attributeBytes(attributes []*raw.Attribute, typ uint) []byte {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == typ {
			return attribute.Value
		}
	}
	return nil
}

func ignoreMissingObject(err error) error {
	if raw.IsError(err, raw.CKR_OBJECT_HANDLE_INVALID) || raw.IsError(err, raw.CKR_SESSION_HANDLE_INVALID) {
		return nil
	}
	return err
}

// AugmentCapabilities reports operations implemented through proprietary
// mechanisms even though the standard CKF_ENCAPSULATE/CKF_DECAPSULATE model is
// not used by QuantumProtect.
//
// QuantumProtect firmware never enumerates its vendor-defined mechanisms
// through C_GetMechanismList and rejects them in C_GetMechanismInfo, so when
// the caller declared QuantumProtect via WithQuantumProtect the mechanisms are
// synthesised into the capability map instead of being probed.
func (m *Module) AugmentCapabilities(fingerprint pkcs11.Fingerprint, capabilities *pkcs11.Capabilities) {
	if capabilities == nil {
		return
	}
	if m.quantumProtect {
		if capabilities.Mechanisms == nil {
			capabilities.Mechanisms = make(map[raw.MechanismType]raw.MechanismInfo)
		}
		for mechanism, info := range quantumProtectMechanisms() {
			capabilities.Mechanisms[raw.MechanismType(mechanism)] = info
		}
	}
	has := func(mechanism uint) bool {
		if _, ok := capabilities.Mechanisms[raw.MechanismType(mechanism)]; ok {
			return true
		}
		return hasMechanism(fingerprint, mechanism)
	}
	ensure := func(algorithm pkcs11.Algorithm) pkcs11.AlgorithmCapability {
		if capabilities.Algorithms == nil {
			capabilities.Algorithms = make(map[pkcs11.Algorithm]pkcs11.AlgorithmCapability)
		}
		return capabilities.Algorithms[algorithm]
	}
	put := func(algorithm pkcs11.Algorithm, value pkcs11.AlgorithmCapability) {
		capabilities.Algorithms[algorithm] = value
	}

	for _, algorithm := range []pkcs11.Algorithm{pkcs11.AlgorithmMLDSA44, pkcs11.AlgorithmMLDSA65, pkcs11.AlgorithmMLDSA87} {
		value := ensure(algorithm)
		value.KeyGeneration = value.KeyGeneration || has(MechanismMLDSAKeyPairGen)
		value.Sign = value.Sign || has(MechanismMLDSASign)
		value.Verify = value.Verify || has(MechanismMLDSAVerify)
		put(algorithm, value)
		capabilities.MLDSA = capabilities.MLDSA || value.KeyGeneration || value.Sign || value.Verify
	}
	for _, algorithm := range []pkcs11.Algorithm{pkcs11.AlgorithmMLKEM512, pkcs11.AlgorithmMLKEM768, pkcs11.AlgorithmMLKEM1024} {
		value := ensure(algorithm)
		value.KeyGeneration = value.KeyGeneration || has(MechanismMLKEMKeyPairGen)
		value.Encapsulate = value.Encapsulate || has(MechanismMLKEMEncapsulate)
		value.Decapsulate = value.Decapsulate || has(MechanismMLKEMDecapsulate)
		put(algorithm, value)
		capabilities.MLKEM = capabilities.MLKEM || value.KeyGeneration || value.Encapsulate || value.Decapsulate
	}

	hbs := []struct {
		algorithm pkcs11.Algorithm
		generate  uint
		sign      uint
		verify    uint
	}{
		{pkcs11.AlgorithmHSS, MechanismHSSKeyGen, MechanismHSSSign, MechanismHSSVerify},
		{pkcs11.AlgorithmLMS, MechanismLMSKeyGen, MechanismLMSSign, MechanismLMSVerify},
		{pkcs11.AlgorithmXMSS, MechanismXMSSKeyGen, MechanismXMSSSign, MechanismXMSSVerify},
		{pkcs11.AlgorithmXMSSMT, MechanismXMSSKeyGen, MechanismXMSSSign, MechanismXMSSVerify},
	}
	for _, item := range hbs {
		value := ensure(item.algorithm)
		value.KeyGeneration = value.KeyGeneration || has(item.generate)
		value.Sign = value.Sign || has(item.sign)
		value.Verify = value.Verify || has(item.verify)
		put(item.algorithm, value)
	}
	capabilities.HSS = capabilities.HSS || capabilities.Algorithms[pkcs11.AlgorithmHSS].KeyGeneration
	capabilities.XMSS = capabilities.XMSS || capabilities.Algorithms[pkcs11.AlgorithmXMSS].KeyGeneration
	capabilities.XMSSMT = capabilities.XMSSMT || capabilities.Algorithms[pkcs11.AlgorithmXMSSMT].KeyGeneration
	capabilities.PQC = capabilities.PQC || capabilities.MLDSA || capabilities.MLKEM || capabilities.HSS || capabilities.XMSS || capabilities.XMSSMT
}
