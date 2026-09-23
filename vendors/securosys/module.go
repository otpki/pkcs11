// Package securosys provides the Securosys Primus vendor module.
package securosys

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// ID is the stable VendorModule identifier for Securosys Primus.
const ID pkcs11.AdapterFamily = "securosys-primus"

// Module implements the Securosys Primus integration behind the root
// pkcs11.VendorModule contract. It is immutable and safe for concurrent use.
type Module struct{ pkcs11.VendorBase }

// New constructs the Securosys Primus vendor module.
func New() pkcs11.VendorModule {
	return &Module{}
}

// Definition describes discovery, matching, proprietary identifiers, and the
// behavior contract for Primus PKCS #11 clients (libprimusP11).
func (*Module) Definition() pkcs11.VendorDefinition {
	id := func(value uint) pkcs11.NumericID { return pkcs11.NumericID(value) }
	return pkcs11.VendorDefinition{
		ID: ID, Name: "Securosys Primus", Priority: 100,
		Source:    "Securosys Primus PKCS #11 SDK 2.6 headers and verified Primus HSM behavior",
		Match:     pkcs11.VendorMatchSpec{Manufacturers: []string{"securosys"}, LibraryDescriptions: []string{"primus", "securosys"}, Models: []string{"primus"}, ModulePaths: []string{"primus", "libprimusp11"}},
		Discovery: pkcs11.VendorDiscovery{EnvironmentVariables: []string{"SECUROSYS_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libprimusP11.so"}, "darwin": {"libprimusP11.dylib"}, "windows": {"primusP11.dll"}}, SearchDirectories: map[string][]string{"linux": {"/opt/securosys/lib"}}},
		Catalog: pkcs11.VendorCatalog{
			Level:  pkcs11.CatalogVendorSDKRequired,
			Source: "Securosys Primus PKCS #11 SDK 2.6 headers (primus/include/pkcs11.h)",
			Mechanisms: map[string]pkcs11.NumericID{
				"ska-rsa-key-pair-gen":        id(MechanismSKARSAPKCSKeyPairGen),
				"ska-dsa-key-pair-gen":        id(MechanismSKADSAKeyPairGen),
				"ska-ec-key-pair-gen":         id(MechanismSKAECKeyPairGen),
				"ska-ec-edwards-key-pair-gen": id(MechanismSKAECEdwardsKeyPairGen),
				"rks-rsa-key-pair-gen":        id(MechanismRKSRSAKeyPairGen),
				"rks-ec-key-pair-gen":         id(MechanismRKSECKeyPairGen),
			},
			Attributes: map[string]pkcs11.NumericID{
				"ska-blocked":              id(AttributeSKABlocked),
				"ska-sensitive-public-key": id(AttributeSKASensitivePublicKey),
				"ska-usage-access-blob":    id(AttributeSKAUsageAccessBlob),
				"ska-block-access-blob":    id(AttributeSKABlockAccessBlob),
				"ska-unblock-access-blob":  id(AttributeSKAUnblockAccessBlob),
				"ska-modify-access-blob":   id(AttributeSKAModifyAccessBlob),
				"rks-attestation-sign":     id(AttributeRKSAttestationSign),
				"rks-certificate-chain":    id(AttributeRKSCertificateChain),
			},
		},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires Primus client and HSM access"},
	}
}

// NormalizeTemplate applies the Primus key-generation template contract. The
// PKCS #11 v3.2 implementation requires placeholder attributes it fills in
// during C_GenerateKeyPair: a one-byte CKA_VALUE on both templates and an empty
// CKA_SEED on the private template. These are added only when absent so
// caller-supplied values still win.
func (*Module) NormalizeTemplate(context pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := pkcs11.CloneAttributes(attributes)
	var private bool
	switch context.Operation {
	case "C_GenerateKeyPair/public":
		private = false
	case "C_GenerateKeyPair/private":
		private = true
	default:
		return result, nil
	}
	keyType, ok := pkcs11.AttributeULong(result, raw.CKA_KEY_TYPE)
	if !ok {
		return result, nil
	}
	switch keyType {
	case raw.CKK_ML_DSA, raw.CKK_ML_KEM, raw.CKK_SLH_DSA:
	default:
		return result, nil
	}
	if !hasAttribute(result, raw.CKA_VALUE) {
		result = append(result, raw.NewAttribute(raw.CKA_VALUE, []byte{0x00}))
	}
	if private && !hasAttribute(result, raw.CKA_SEED) {
		result = append(result, raw.NewAttribute(raw.CKA_SEED, nil))
	}
	return result, nil
}

// ClassifyError maps Securosys vendor return values to recovery actions. Login
// failures and the missing permanent-secret bootstrap remain terminal so they
// surface to the caller unchanged.
func (*Module) ClassifyError(context pkcs11.VendorErrorContext, err error) pkcs11.RecoveryAction {
	action := context.StandardAction
	switch {
	case raw.IsError(err, ErrorNotLoggedIn):
		action = max(action, pkcs11.RecoveryRelogin)
	case raw.IsError(err, ErrorHSMUnreachable):
		action = max(action, pkcs11.RecoveryReplaceSession)
	}
	return action
}

func hasAttribute(attributes []*raw.Attribute, typ uint) bool {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == typ {
			return true
		}
	}
	return false
}
