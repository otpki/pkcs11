// Package provider demonstrates a consumer-owned VendorModule package.
//
// A real implementation can live in another repository. The root pkcs11
// package does not need to know its import path or identifier in advance.
package provider

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable identity used by detection diagnostics and conformance.
const ID pkcs11.AdapterFamily = "example-acme-hsm"

// New constructs the immutable module. This example is declarative: standard
// PKCS #11 operations require no custom hooks, but discovery and low-level
// session facts still belong to the provider package.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID:       ID,
		Name:     "Example Acme HSM",
		Priority: 100,
		Source:   "example integration contract",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"acme security"},
			Models:        []string{"acme hsm"},
			ModulePaths:   []string{"acmepkcs11"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"ACME_PKCS11_MODULE"},
			ModuleNames: map[string][]string{
				"linux":   {"libacmepkcs11.so"},
				"darwin":  {"libacmepkcs11.dylib"},
				"windows": {"acmepkcs11.dll"},
			},
		},
		Catalog: pkcs11.VendorCatalog{
			Level:  pkcs11.CatalogStandardOnly,
			Source: "example integration contract",
		},
		Behavior: pkcs11.VendorBehavior{
			LoginScope:    pkcs11.VendorLoginToken,
			NetworkBacked: true,
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "requires provider hardware or a simulator",
		},
	})
}
