// Package p11kit provides the p11-kit proxy vendor module.
package p11kit

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for p11-kit proxy.
const ID pkcs11.AdapterFamily = "p11-kit-proxy"

// New constructs the p11-kit proxy vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "p11-kit Proxy", Priority: 60, Source: "p11-kit",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"p11-kit"}, LibraryDescriptions: []string{"p11-kit", "proxy"}, ModulePaths: []string{"p11-kit-proxy"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"P11_KIT_PROXY_MODULE"}, ModuleNames: map[string][]string{"linux": {"p11-kit-proxy.so"}, "darwin": {"p11-kit-proxy.dylib"}, "windows": {"p11-kit-proxy.dll"}}, SearchDirectories: map[string][]string{"linux": {"/usr/lib/p11-kit", "/usr/lib64/p11-kit"}, "darwin": {"/usr/local/opt/p11-kit/lib/p11-kit", "/opt/homebrew/opt/p11-kit/lib/p11-kit"}}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogStandardOnly, Source: "p11-kit"},
		Conformance: pkcs11.VendorConformance{Notes: "Run against the modules configured behind p11-kit proxy"},
	})
}
