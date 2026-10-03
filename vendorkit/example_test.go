package vendorkit_test

import (
	"fmt"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ExampleMustNew shows the smallest out-of-tree provider implementation. The
// resulting module can be passed directly through pkcs11.Config.Vendors.
func ExampleMustNew() {
	module := vendorkit.MustNew(pkcs11.VendorDefinition{
		ID:       "acme-hsm",
		Name:     "Acme HSM",
		Priority: 100,
		Source:   "Acme PKCS #11 SDK 4.2 integration guide",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"acme"},
			Models:        []string{"acme hsm"},
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"ACME_PKCS11_MODULE"},
			ModuleNames: map[string][]string{
				"linux":   {"libacmepkcs11.so"},
				"darwin":  {"libacmepkcs11.dylib"},
				"windows": {"acmepkcs11.dll"},
			},
		},
		Behavior: pkcs11.VendorBehavior{
			LoginScope:    pkcs11.VendorLoginToken,
			NetworkBacked: true,
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "requires an Acme HSM or licensed simulator",
		},
	})

	definition := module.Definition()
	fmt.Println(definition.ID, definition.Discovery.EnvironmentVariables[0])
	// Output: acme-hsm ACME_PKCS11_MODULE
}

// ExampleMustDecorate shows how a consumer can add reviewed identifiers from a
// licensed SDK without forking or replacing a provider's operational hooks.
func ExampleMustDecorate() {
	base := vendorkit.MustNew(pkcs11.VendorDefinition{
		ID:     "acme-hsm",
		Name:   "Acme HSM",
		Source: "public Acme integration guide",
		Match:  pkcs11.VendorMatchSpec{Manufacturers: []string{"acme"}},
		Discovery: pkcs11.VendorDiscovery{
			ModuleNames: map[string][]string{"linux": {"libacmepkcs11.so"}},
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "requires Acme hardware",
		},
	})

	module := vendorkit.MustDecorate(base, func(definition *pkcs11.VendorDefinition) {
		definition.Source = "Acme SDK 4.2 licensed header, reviewed internally"
		definition.Catalog.Level = pkcs11.CatalogPublic
		definition.Catalog.Mechanisms = map[string]pkcs11.NumericID{
			"acme-backup-key": 0x80000001,
		}
	})

	definition := module.Definition()
	fmt.Printf("%s %#x\n", definition.ID, definition.Catalog.Mechanisms["acme-backup-key"])
	// Output: acme-hsm 0x80000001
}
