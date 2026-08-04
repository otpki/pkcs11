// Package kryoptic provides a PKCS #11 3.x software-provider module used for
// standard and post-quantum conformance testing.
package kryoptic

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Kryoptic.
const ID pkcs11.AdapterFamily = "kryoptic"

// New returns the Kryoptic vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Kryoptic", Priority: 75, Source: "Kryoptic project",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"kryoptic"}, LibraryDescriptions: []string{"kryoptic"}, ModulePaths: []string{"libkryoptic", "kryoptic"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"KRYOPTIC_PKCS11_MODULE"}, ModuleNames: map[string][]string{"linux": {"libkryoptic_pkcs11.so", "libkryoptic.so"}, "darwin": {"libkryoptic_pkcs11.dylib"}}},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginSession},
		Conformance: pkcs11.VendorConformance{Provider: "kryoptic-pqc", Notes: "Public software PKCS #11 provider used for PKCS #11 3.2/PQC CI coverage."},
	})
}
