// Package nshield provides the Entrust nShield vendor module.
package nshield

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Entrust nShield.
const ID pkcs11.AdapterFamily = "entrust-nshield"

// New constructs the Entrust nShield vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Entrust nShield", Priority: 105,
		Source:    "Entrust nShield PKCS #11 client metadata; v3.2 PQC surface verified on nShield 5c firmware 13.8.6",
		Match:     pkcs11.VendorMatchSpec{Manufacturers: []string{"entrust", "ncipher"}, LibraryDescriptions: []string{"nfast", "nshield"}, Models: []string{"nshield", "nfast"}, ModulePaths: []string{"libcknfast", "cknfast"}},
		Discovery: pkcs11.VendorDiscovery{EnvironmentVariables: []string{"NFAST_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libcknfast.so"}, "darwin": {"libcknfast.dylib"}, "windows": {"cknfast.dll"}}, SearchDirectories: map[string][]string{"linux": {"/opt/nfast/toolkits/pkcs11"}}},
		Catalog:   pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "Entrust SDK required for unpublished extensions"},
		Behavior:  pkcs11.VendorBehavior{NetworkBacked: true},
		// libcknfast declares Cryptoki 3.2 and reaches ML-DSA, SLH-DSA, ML-KEM,
		// and Ed25519 over standard mechanisms. It rejects key-generation
		// placeholder attributes (CKA_VALUE/CKA_SEED), so no template
		// normalization is installed here.
		Conformance: pkcs11.VendorConformance{Notes: "Requires nShield client software and HSM access; verified on nShield 5c firmware 13.8.6"},
	})
}
