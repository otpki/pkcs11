// Package opensc provides the OpenSC vendor module.
package opensc

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for OpenSC.
const ID pkcs11.AdapterFamily = "opensc"

// New constructs the OpenSC vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "OpenSC", Priority: 45, Source: "OpenSC",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"opensc"}, LibraryDescriptions: []string{"opensc"}, ModulePaths: []string{"opensc-pkcs11"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"OPENSC_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"opensc-pkcs11.so"}, "darwin": {"opensc-pkcs11.dylib"}, "windows": {"opensc-pkcs11.dll"}}, SearchDirectories: map[string][]string{"darwin": {"/Library/OpenSC/lib"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogStandardOnly, Source: "OpenSC"},
		Behavior:    pkcs11.VendorBehavior{ForceSerialSessions: true, MaxSessions: 1},
		Conformance: pkcs11.VendorConformance{Notes: "Requires a supported smart card/token"},
	})
}
