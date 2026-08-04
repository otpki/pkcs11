// Package googlekms provides the Google Cloud KMS PKCS #11 vendor module and
// public kmsp11 extension identifiers.
package googlekms

import (
	"fmt"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

const (
	// ID is the stable VendorModule identifier for Google Cloud KMS PKCS #11.
	ID pkcs11.AdapterFamily = "google-cloud-kms"

	// AttributeBase is the base of Google's public kmsp11 attribute namespace.
	AttributeBase uint = 0x8001e100
	// AttributeAlgorithm selects the Cloud KMS key algorithm during generation.
	AttributeAlgorithm uint = AttributeBase | 0x01
	// AttributeProtectionLevel selects software, HSM, or external protection.
	AttributeProtectionLevel uint = AttributeBase | 0x02
	// AttributeCryptoKeyBackend selects a configured Cloud KMS backend resource.
	AttributeCryptoKeyBackend uint = AttributeBase | 0x03
	// MechanismBase is the base of Google's public kmsp11 mechanism namespace.
	MechanismBase uint = 0x8001e100
	// MechanismAESGCM is Google's generated-IV AES-GCM mechanism.
	MechanismAESGCM uint = MechanismBase | 0x01
	// ProtectionSoftware requests a software-protected Cloud KMS key.
	ProtectionSoftware uint = 1
	// ProtectionHSM requests a Cloud HSM-protected key.
	ProtectionHSM uint = 2
	// ProtectionExternal requests an externally protected key.
	ProtectionExternal uint = 3
)

// Module implements Google kmsp11 mechanism and template conventions.
// It is stateless, immutable, and safe for concurrent use.
type Module struct{ pkcs11.VendorBase }

// New returns the Google Cloud KMS module.
func New() pkcs11.VendorModule { return &Module{} }

// Definition returns Google matching, discovery, catalog, behavior, and conformance metadata.
func (*Module) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID: ID, Name: "Google Cloud KMS PKCS #11", Priority: 95,
		Source: "Google Cloud KMS kms-integrations kmsp11.h",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"google"}, LibraryDescriptions: []string{"cloud kms", "cloud hsm", "google"},
			Models: []string{"cloud kms", "cloud hsm"}, ModulePaths: []string{"libkmsp11", "kmsp11"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"GOOGLE_KMS_PKCS11_MODULE"},
			ModuleNames: map[string][]string{
				"linux": {"libkmsp11.so"}, "darwin": {"libkmsp11.dylib"}, "windows": {"kmsp11.dll"},
			},
		},
		Catalog: pkcs11.VendorCatalog{
			Level: pkcs11.CatalogPublic, Source: "Google Cloud KMS kmsp11.h",
			Mechanisms: map[string]pkcs11.NumericID{"google-kms-aes-gcm": pkcs11.NumericID(MechanismAESGCM)},
			Attributes: map[string]pkcs11.NumericID{
				"google-kms-algorithm":          pkcs11.NumericID(AttributeAlgorithm),
				"google-kms-protection-level":   pkcs11.NumericID(AttributeProtectionLevel),
				"google-kms-crypto-key-backend": pkcs11.NumericID(AttributeCryptoKeyBackend),
			},
		},
		Behavior: pkcs11.VendorBehavior{
			LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true,
			GCMIVMode: pkcs11.VendorGCMIVParameter, GCMIVSize: 12,
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires Google Cloud credentials and kmsp11 configuration",
		},
	}
}

// NormalizeMechanism translates standard AES-GCM to Google's generated-IV mechanism.
func (*Module) NormalizeMechanism(context pkcs11.VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
	if mechanism == nil {
		return nil, fmt.Errorf("googlekms: nil mechanism")
	}
	result := &raw.Mechanism{Mechanism: mechanism.Mechanism, Parameter: mechanism.Parameter}
	if result.Mechanism != raw.CKM_AES_GCM || !context.Device.Capabilities.HasMechanism(MechanismAESGCM) {
		return result, nil
	}
	result.Mechanism = MechanismAESGCM
	var params *raw.GCMParams
	switch value := result.Parameter.(type) {
	case nil:
		params = &raw.GCMParams{}
	case raw.GCMParams:
		copy := value
		params = &copy
	case *raw.GCMParams:
		if value != nil {
			copy := *value
			copy.IV = append([]byte(nil), value.IV...)
			copy.AAD = append([]byte(nil), value.AAD...)
			params = &copy
		}
	default:
		return nil, fmt.Errorf("googlekms: AES-GCM requires raw.GCMParams, got %T", result.Parameter)
	}
	if params == nil {
		params = &raw.GCMParams{}
	}
	if len(params.IV) == 0 {
		params.IV = make([]byte, 12)
	}
	if len(params.IV) != 12 {
		return nil, fmt.Errorf("googlekms: generated-IV AES-GCM requires a 12-byte IV buffer")
	}
	params.IVBits = 96
	if params.TagBits == 0 {
		params.TagBits = 128
	}
	result.Parameter = params
	return result, nil
}

// NormalizeTemplate enforces the object-template subset implemented by kmsp11.
func (*Module) NormalizeTemplate(context pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := pkcs11.CloneAttributes(attributes)
	class, _ := pkcs11.AttributeULong(result, raw.CKA_CLASS)
	if class == raw.CKO_CERTIFICATE {
		return nil, fmt.Errorf("googlekms: writable certificate objects are not supported")
	}
	if class != raw.CKO_PUBLIC_KEY {
		return result, nil
	}
	if context.Operation == "C_GenerateKeyPair/public" {
		// kmsp11 owns the cloud public-key object metadata and requires an empty
		// public template during key-pair creation.
		return nil, nil
	}
	return pkcs11.RemoveAttributes(result,
		raw.CKA_TOKEN, raw.CKA_PRIVATE, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE,
		raw.CKA_DESTROYABLE, raw.CKA_ENCRYPT, raw.CKA_VERIFY, raw.CKA_WRAP,
	), nil
}
