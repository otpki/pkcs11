// Package crypto4a provides the Crypto4A QxHSM vendor module.
package crypto4a

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Crypto4A QxHSM.
const ID pkcs11.AdapterFamily = "crypto4a-qxhsm"

// New constructs the Crypto4A QxHSM vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Crypto4A QxHSM", Priority: 110,
		Source:      "Crypto4A public product metadata; proprietary SDK identifiers supplied by a consumer module when required",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"crypto4a"}, LibraryDescriptions: []string{"qxhsm", "crypto4a"}, Models: []string{"qxhsm"}, ModulePaths: []string{"qxhsm", "qxp11"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"CRYPTO4A_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libqxhsm_pkcs11.so"}, "windows": {"qxhsm-pkcs11.dll"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "Crypto4A SDK required for unpublished extensions"},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires a QxHSM or licensed simulator/runtime"},
	})
}
