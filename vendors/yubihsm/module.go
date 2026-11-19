// Package yubihsm provides the YubiHSM 2 vendor module and public pkcs11y.h
// wrapping identifiers.
package yubihsm

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

const (
	// ID is the stable VendorModule identifier for YubiHSM 2.
	ID pkcs11.AdapterFamily = "yubihsm2"
	// BaseVendor is Yubico's assigned PKCS #11 vendor namespace base.
	BaseVendor uint = 0x59554200
	// KeyTypeAES128CCMWrap identifies a 128-bit YubiHSM AES-CCM wrapping key.
	KeyTypeAES128CCMWrap uint = 0xd955421d
	// KeyTypeAES192CCMWrap identifies a 192-bit YubiHSM AES-CCM wrapping key.
	KeyTypeAES192CCMWrap uint = 0xd9554229
	// KeyTypeAES256CCMWrap identifies a 256-bit YubiHSM AES-CCM wrapping key.
	KeyTypeAES256CCMWrap uint = 0xd955422a
	// MechanismAESCCMWrap is YubiHSM's AES-CCM key wrapping mechanism.
	MechanismAESCCMWrap uint = 0xd9554204
)

// Module implements the YubiHSM 2 vendor behavior and proxy parameter codecs.
type Module struct {
	pkcs11.VendorBase
	definition pkcs11.VendorDefinition
}

// New constructs the YubiHSM 2 vendor module.
func New() pkcs11.VendorModule {
	return &Module{definition: pkcs11.VendorDefinition{
		ID: ID, Name: "YubiHSM 2", Priority: 90, Source: "Yubico yubihsm-shell pkcs11y.h",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"yubico"}, LibraryDescriptions: []string{"yubihsm"}, Models: []string{"yubihsm"}, ModulePaths: []string{"yubihsm_pkcs11", "yubihsm"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"YUBIHSM_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libyubihsm_pkcs11.so"}, "darwin": {"libyubihsm_pkcs11.dylib"}, "windows": {"yubihsm_pkcs11.dll"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogPublic, Source: "Yubico yubihsm-shell pkcs11y.h", Mechanisms: map[string]pkcs11.NumericID{"yubihsm-aes-ccm-wrap": pkcs11.NumericID(MechanismAESCCMWrap)}, KeyTypes: map[string]pkcs11.NumericID{"yubihsm-aes128-ccm-wrap": pkcs11.NumericID(KeyTypeAES128CCMWrap), "yubihsm-aes192-ccm-wrap": pkcs11.NumericID(KeyTypeAES192CCMWrap), "yubihsm-aes256-ccm-wrap": pkcs11.NumericID(KeyTypeAES256CCMWrap)}},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, MaxSessions: 16, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires YubiHSM Connector and a YubiHSM 2"},
	}}
}

// Definition returns an immutable snapshot of the YubiHSM definition.
func (module *Module) Definition() pkcs11.VendorDefinition {
	if module == nil {
		return pkcs11.VendorDefinition{}
	}
	return pkcs11.CloneVendorDefinition(module.definition)
}

// NormalizeTemplate removes policy attributes yubihsm_pkcs11 refuses. YubiHSM
// objects are never modifiable or copyable, and the module accepts those
// attributes only as false; it does not accept CKA_ALWAYS_AUTHENTICATE in a
// generation template, so a false value, which matches the device, is dropped.
func (*Module) NormalizeTemplate(_ pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := pkcs11.RemoveAttributes(attributes, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE)
	for _, attribute := range result {
		if attribute.Type == raw.CKA_ALWAYS_AUTHENTICATE && isFalse(attribute) {
			return pkcs11.RemoveAttributes(result, raw.CKA_ALWAYS_AUTHENTICATE), nil
		}
	}
	return result, nil
}

func isFalse(attribute *raw.Attribute) bool {
	return len(attribute.Value) == 1 && attribute.Value[0] == 0
}
