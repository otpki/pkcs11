// Package fortanix provides the Fortanix DSM vendor module.
package fortanix

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Fortanix DSM.
const ID pkcs11.AdapterFamily = "fortanix-dsm"

// New constructs the Fortanix DSM vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Fortanix DSM", Priority: 100, Source: "Fortanix DSM PKCS #11 client metadata",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"fortanix"}, LibraryDescriptions: []string{"fortanix", "dsm", "sdkms"}, Models: []string{"dsm", "sdkms"}, ModulePaths: []string{"sdkms", "fortanix"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"FORTANIX_PKCS11_LIB"}, ModuleNames: map[string][]string{"linux": {"fortanix_pkcs11.so", "sdkms-pkcs11.so"}, "darwin": {"fortanix_pkcs11.dylib"}, "windows": {"fortanix_pkcs11.dll"}}, SearchDirectories: map[string][]string{"linux": {"/opt/fortanix/pkcs11"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "Fortanix SDK required for unpublished extensions"},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires Fortanix DSM credentials and client runtime"},
	})
}
