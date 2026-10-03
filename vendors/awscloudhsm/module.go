// Package awscloudhsm provides the AWS CloudHSM vendor module and its public
// PKCS #11 extension identifiers.
package awscloudhsm

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

const (
	// ID is the stable VendorModule identifier for AWS CloudHSM.
	ID pkcs11.AdapterFamily = "aws-cloudhsm"

	// MechanismSP800108CounterKDF is AWS CloudHSM's counter-mode SP 800-108 KDF.
	MechanismSP800108CounterKDF uint = 0x80000001
	// MechanismAESGCM is AWS CloudHSM's generated-IV AES-GCM mechanism.
	MechanismAESGCM uint = 0x80001087
	// MechanismAESKeyWrapNoPad is AWS CloudHSM AES key wrap without padding.
	MechanismAESKeyWrapNoPad uint = 0x80002109
	// MechanismAESKeyWrapPKCS5 is AWS CloudHSM AES key wrap with PKCS #5 padding.
	MechanismAESKeyWrapPKCS5 uint = 0x8000210a
	// MechanismAESKeyWrapZeroPad is AWS CloudHSM AES key wrap with zero padding.
	MechanismAESKeyWrapZeroPad uint = 0x8000216f
)

// Module implements AWS-specific mechanism normalization and output handling.
// It is stateless, immutable, and safe for concurrent use.
type Module struct{ pkcs11.VendorBase }

// New returns the AWS CloudHSM module.
func New() pkcs11.VendorModule { return &Module{} }

// Definition returns AWS matching, discovery, catalog, behavior, and conformance metadata.
func (*Module) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID: ID, Name: "AWS CloudHSM", Priority: 105,
		Source: "AWS CloudHSM Client SDK documentation",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers:       []string{"amazon", "aws", "cavium"},
			LibraryDescriptions: []string{"cloudhsm", "cavium"}, Models: []string{"cloudhsm"},
			ModulePaths: []string{"cloudhsm", "libcloudhsm_pkcs11"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"AWS_CLOUDHSM_PKCS11_LIB", "CLOUDHSM_PKCS11_LIB"},
			ModuleNames: map[string][]string{
				"linux": {"libcloudhsm_pkcs11.so"}, "windows": {"cloudhsm_pkcs11.dll"},
			},
			SearchDirectories: map[string][]string{"linux": {"/opt/cloudhsm/lib"}},
		},
		Catalog: pkcs11.VendorCatalog{
			Level: pkcs11.CatalogPublic, Source: "AWS CloudHSM Client SDK documentation",
			Mechanisms: map[string]pkcs11.NumericID{
				"aws-sp800-108-counter-kdf": pkcs11.NumericID(MechanismSP800108CounterKDF),
				"aws-aes-gcm":               pkcs11.NumericID(MechanismAESGCM),
				"aws-aes-key-wrap-no-pad":   pkcs11.NumericID(MechanismAESKeyWrapNoPad),
				"aws-aes-key-wrap-pkcs5":    pkcs11.NumericID(MechanismAESKeyWrapPKCS5),
				"aws-aes-key-wrap-zero-pad": pkcs11.NumericID(MechanismAESKeyWrapZeroPad),
			},
		},
		Behavior: pkcs11.VendorBehavior{
			LoginScope: pkcs11.VendorLoginToken, ReadWriteSessionsOnly: true,
			NetworkBacked: true, GCMIVMode: pkcs11.VendorGCMIVCiphertextPrefix,
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires CloudHSM client configuration and cluster credentials",
		},
	}
}

// NormalizeMechanism applies CloudHSM OAEP restrictions and generated-IV GCM semantics.
func (*Module) NormalizeMechanism(context pkcs11.VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
	if mechanism == nil {
		return nil, errors.New("awscloudhsm: nil mechanism")
	}
	result := &raw.Mechanism{Mechanism: mechanism.Mechanism, Parameter: mechanism.Parameter}
	if params, ok := result.Parameter.(raw.OAEPParams); ok && len(params.SourceData) != 0 {
		return nil, errors.New("awscloudhsm: non-empty RSA-OAEP labels are not supported")
	}
	if params, ok := result.Parameter.(*raw.OAEPParams); ok && params != nil && len(params.SourceData) != 0 {
		return nil, errors.New("awscloudhsm: non-empty RSA-OAEP labels are not supported")
	}
	if result.Mechanism != raw.CKM_AES_GCM || !context.Device.Capabilities.HasMechanism(MechanismAESGCM) {
		return result, nil
	}
	result.Mechanism = MechanismAESGCM
	var params *raw.GCMParams
	switch value := result.Parameter.(type) {
	case nil:
		params = &raw.GCMParams{}
	case raw.GCMParams:
		copied := value
		params = &copied
	case *raw.GCMParams:
		if value != nil {
			copied := *value
			copied.IV = slices.Clone(value.IV)
			copied.AAD = slices.Clone(value.AAD)
			params = &copied
		}
	default:
		return nil, fmt.Errorf("awscloudhsm: AES-GCM requires raw.GCMParams, got %T", result.Parameter)
	}
	params = cmp.Or(params, &raw.GCMParams{})
	// CKM_CLOUDHSM_AES_GCM requires a null IV pointer. Encryption prefixes the
	// generated IV to the ciphertext; decryption consumes that same combined form.
	params.IV = nil
	params.IVBits = 0
	params.TagBits = cmp.Or(params.TagBits, 128)
	result.Parameter = params
	return result, nil
}

// FinalizeEncryption records that proprietary GCM ciphertext already contains its IV.
func (*Module) FinalizeEncryption(context pkcs11.VendorCipherContext, result pkcs11.EncryptionResult) (pkcs11.EncryptionResult, error) {
	if context.Route.Mechanism != nil && context.Route.Mechanism.Mechanism == raw.CKM_AES_GCM && context.Device.Capabilities.HasMechanism(MechanismAESGCM) {
		result.IV = nil
	}
	return result, nil
}
