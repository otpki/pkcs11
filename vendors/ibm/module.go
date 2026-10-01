// Package ibm provides the IBM HPCS/openCryptoki vendor module and public EP11
// key types, attributes, and ML-KEM parameter structure.
package ibm

import (
	"errors"
	"fmt"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

const (
	// ID is the stable VendorModule identifier for IBM HPCS/openCryptoki grep11.
	ID pkcs11.AdapterFamily = "ibm-hpcs"

	// KeyTypeDilithium is IBM's legacy Dilithium key type.
	KeyTypeDilithium uint = 0x80010023
	// KeyTypeKyber is IBM's legacy Kyber key type.
	KeyTypeKyber uint = 0x80010024
	// KeyTypeMLDSA is IBM's ML-DSA key type.
	KeyTypeMLDSA uint = 0x80010025
	// KeyTypeMLKEM is IBM's ML-KEM key type.
	KeyTypeMLKEM uint = 0x80010026

	// The following values are public IBM/openCryptoki object attributes.
	// AttributeOpaque stores an IBM opaque-key blob.
	AttributeOpaque uint = 0x80000001
	// The following values are public IBM/openCryptoki object attributes.
	// AttributeOpaqueReenc stores a re-enciphered IBM opaque-key blob.
	AttributeOpaqueReenc uint = 0x80000003
	// AttributeRestrictable marks whether IBM policy restrictions may be applied.
	AttributeRestrictable uint = 0x80010001
	// AttributeNeverModifiable marks an object whose IBM policy may never be modified.
	AttributeNeverModifiable uint = 0x80010002
	// AttributeRetainKey requests retention of key material in the IBM backend.
	AttributeRetainKey uint = 0x80010003
	// AttributeAttrBound binds IBM object attributes to the protected key.
	AttributeAttrBound uint = 0x80010004
	// AttributeKeyType carries IBM's internal key-type selector.
	AttributeKeyType uint = 0x80010005
	// AttributeStructParams carries IBM structured algorithm parameters.
	AttributeStructParams uint = 0x80010009
	// AttributeParameterSet carries IBM's proprietary PQC parameter-set selector.
	AttributeParameterSet uint = 0x80010010
	// AttributeProtKeyExtractable controls protected-key extraction.
	AttributeProtKeyExtractable uint = 0x8001000c
	// AttributeProtKeyNeverExtractable records that protected-key extraction was never permitted.
	AttributeProtKeyNeverExtractable uint = 0x8001000d
	// AttributeMLKEMPK contains IBM ML-KEM public-key bytes.
	AttributeMLKEMPK uint = 0x800d000a
	// AttributeMLKEMSK contains IBM ML-KEM secret-key bytes.
	AttributeMLKEMSK uint = 0x800d000b
)

// MLKEMMode selects IBM ML-KEM encapsulation or decapsulation.
type MLKEMMode uint

const (
	// MLKEMEncapsulate requests encapsulation.
	MLKEMEncapsulate MLKEMMode = 1
	// MLKEMDecapsulate requests decapsulation.
	MLKEMDecapsulate MLKEMMode = 2
)

// MLKEMParams is IBM's pointer-bearing ML-KEM mechanism parameter record.
// MarshalPKCS11Native emits the correct host ABI and relocates slice pointers.
type MLKEMParams struct {
	Version    uint
	Mode       MLKEMMode
	KDF        uint
	Prepend    bool
	Cipher     []byte
	SharedData []byte
	Secret     raw.ObjectHandle
}

// MarshalPKCS11Native implements raw.NativeParameterMarshaler.
func (p *MLKEMParams) MarshalPKCS11Native(abi raw.NativeABI) (raw.NativeParameterLayout, error) {
	if p == nil {
		return raw.NativeParameterLayout{}, errors.New("ibm: nil ML-KEM parameters")
	}
	if p.Mode != MLKEMEncapsulate && p.Mode != MLKEMDecapsulate {
		return raw.NativeParameterLayout{}, fmt.Errorf("ibm: invalid ML-KEM mode %d", p.Mode)
	}
	b := raw.NewNativeStructBuilder(abi)
	b.AddULong(p.Version)
	b.AddULong(uint(p.Mode))
	b.AddULong(p.KDF)
	b.AddBool(p.Prepend)
	b.AddPointer(p.Cipher)
	b.AddULong(uint(len(p.Cipher)))
	b.AddPointer(p.SharedData)
	b.AddULong(uint(len(p.SharedData)))
	b.AddULong(uint(p.Secret))
	return b.Layout(), nil
}

// Module implements IBM-specific PQC template normalization.
// It is stateless, immutable, and safe for concurrent use.
type Module struct{ pkcs11.VendorBase }

// New constructs the IBM HPCS/openCryptoki vendor module.
func New() pkcs11.VendorModule { return &Module{} }

// Definition returns IBM matching, discovery, catalog, behavior, and conformance metadata.
func (*Module) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID: ID, Name: "IBM Hyper Protect Crypto Services", Priority: 100,
		Source: "IBM HPCS/openCryptoki public headers",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"ibm"}, LibraryDescriptions: []string{"hyper protect", "hpcs", "grep11", "greencard"},
			Models: []string{"hpcs", "hyper protect"}, ModulePaths: []string{"grep11"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"IBM_HPCS_PKCS11_MODULE", "GREP11_PKCS11_MODULE"},
			ModuleNames:          map[string][]string{"linux": {"libpkcs11-grep11.so"}, "windows": {"pkcs11-grep11.dll"}},
		},
		Catalog: pkcs11.VendorCatalog{
			Level: pkcs11.CatalogPublic, Source: "IBM HPCS/openCryptoki public headers",
			KeyTypes: map[string]pkcs11.NumericID{
				"dilithium": pkcs11.NumericID(KeyTypeDilithium), "ibm-dilithium": pkcs11.NumericID(KeyTypeDilithium),
				"kyber": pkcs11.NumericID(KeyTypeKyber), "ibm-kyber": pkcs11.NumericID(KeyTypeKyber),
				"ibm-ml-dsa": pkcs11.NumericID(KeyTypeMLDSA), "ibm-ml-kem": pkcs11.NumericID(KeyTypeMLKEM),
			},
			Attributes: map[string]pkcs11.NumericID{
				"ibm-opaque": pkcs11.NumericID(AttributeOpaque), "ibm-opaque-reenc": pkcs11.NumericID(AttributeOpaqueReenc),
				"ibm-restrictable": pkcs11.NumericID(AttributeRestrictable), "ibm-never-modifiable": pkcs11.NumericID(AttributeNeverModifiable),
				"ibm-retain-key": pkcs11.NumericID(AttributeRetainKey), "ibm-attribute-bound": pkcs11.NumericID(AttributeAttrBound),
				"ibm-key-type": pkcs11.NumericID(AttributeKeyType), "ibm-structure-parameters": pkcs11.NumericID(AttributeStructParams),
				"ibm-parameter-set":             pkcs11.NumericID(AttributeParameterSet),
				"ibm-protected-key-extractable": pkcs11.NumericID(AttributeProtKeyExtractable),
				"ibm-ml-kem-public-key":         pkcs11.NumericID(AttributeMLKEMPK), "ibm-ml-kem-secret-key": pkcs11.NumericID(AttributeMLKEMSK),
			},
		},
		Behavior: pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires IBM HPCS/grep11 credentials and middleware",
		},
	}
}

// NormalizeTemplate mirrors standardized parameter-set selectors into IBM attributes.
func (*Module) NormalizeTemplate(_ pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := pkcs11.CloneAttributes(attributes)
	keyType, _ := pkcs11.AttributeULong(result, raw.CKA_KEY_TYPE)
	switch keyType {
	case KeyTypeDilithium, KeyTypeKyber, KeyTypeMLDSA, KeyTypeMLKEM:
		if parameterSet, ok := pkcs11.AttributeULong(result, raw.CKA_PARAMETER_SET); ok {
			if _, exists := pkcs11.AttributeULong(result, AttributeParameterSet); !exists {
				result = pkcs11.MergeAttributes(result, []*raw.Attribute{raw.NewAttribute(AttributeParameterSet, parameterSet)})
			}
		}
	}
	return result, nil
}
