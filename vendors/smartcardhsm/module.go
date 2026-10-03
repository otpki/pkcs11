// Package smartcardhsm provides the SmartCard-HSM/Nitrokey vendor module.
package smartcardhsm

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// ID is the stable VendorModule identifier for SmartCard-HSM/Nitrokey.
const ID pkcs11.AdapterFamily = "smartcard-hsm"

// Module implements SmartCard-HSM template compatibility behavior.
type Module struct{ pkcs11.VendorBase }

// New returns the SmartCard-HSM module.
func New() pkcs11.VendorModule { return &Module{} }

// Definition returns SmartCard-HSM matching, discovery, behavior, and conformance metadata.
func (*Module) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{
		ID: ID, Name: "SmartCard-HSM / Nitrokey", Priority: 88,
		Source: "SmartCard-HSM/OpenSC behavior",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers:       []string{"cardcontact", "nitrokey", "smartcard-hsm"},
			LibraryDescriptions: []string{"smartcard-hsm"}, Models: []string{"smartcard-hsm", "nitrokey"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"SMARTCARD_HSM_PKCS11_MODULE"},
			ModuleNames: map[string][]string{
				"linux": {"opensc-pkcs11.so"}, "darwin": {"opensc-pkcs11.dylib"}, "windows": {"opensc-pkcs11.dll"},
			},
		},
		Catalog: pkcs11.VendorCatalog{Level: pkcs11.CatalogStandardOnly, Source: "SmartCard-HSM/OpenSC"},
		Behavior: pkcs11.VendorBehavior{
			LoginScope: pkcs11.VendorLoginToken, ForceSerialSessions: true, MaxSessions: 1,
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires a SmartCard-HSM or Nitrokey device",
		},
	}
}

// NormalizeTemplate removes policy attributes rejected by common SmartCard-HSM
// middleware versions while leaving object identity and algorithm attributes intact.
func (*Module) NormalizeTemplate(_ pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	return pkcs11.RemoveAttributes(attributes, raw.CKA_MODIFIABLE, raw.CKA_COPYABLE, raw.CKA_DESTROYABLE), nil
}
