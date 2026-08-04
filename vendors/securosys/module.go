// Package securosys provides the Securosys Primus vendor module.
package securosys

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Securosys Primus.
const ID pkcs11.AdapterFamily = "securosys-primus"

// New constructs the Securosys Primus vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Securosys Primus", Priority: 100,
		Source:      "Securosys Primus PKCS #11 client metadata",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"securosys"}, LibraryDescriptions: []string{"primus", "securosys"}, Models: []string{"primus"}, ModulePaths: []string{"primus", "libprimusp11"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"SECUROSYS_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libprimusP11.so"}, "darwin": {"libprimusP11.dylib"}, "windows": {"primusP11.dll"}}, SearchDirectories: map[string][]string{"linux": {"/opt/securosys/lib"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "Securosys SDK required for unpublished extensions"},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires Primus client and HSM access"},
	})
}
