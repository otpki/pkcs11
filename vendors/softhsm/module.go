// Package softhsm provides vendor modules for SoftHSM 2 and SoftHSM 3.
package softhsm

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

const (
	// IDV2 is the stable VendorModule identifier for SoftHSM 2.
	IDV2 pkcs11.AdapterFamily = "softhsm2"
	// IDV3 is the stable VendorModule identifier for SoftHSM 3.
	IDV3 pkcs11.AdapterFamily = "softhsm3"
)

// NewV2 returns the SoftHSM 2 module.
func NewV2() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: IDV2, Name: "SoftHSM 2", Priority: 70, Source: "SoftHSM",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"softhsm"}, Models: []string{"softhsm v2", "softhsm2"},
			ModulePaths: []string{"libsofthsm2", "softhsm2"}, MinimumTextMatches: 2,
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"SOFTHSM2_MODULE"},
			ModuleNames: map[string][]string{
				"linux": {"libsofthsm2.so"}, "darwin": {"libsofthsm2.dylib"}, "windows": {"softhsm2.dll"},
			},
			SearchDirectories: map[string][]string{
				"linux":  {"/usr/lib/softhsm", "/usr/lib64/softhsm", "/usr/local/lib/softhsm", "/usr/lib/x86_64-linux-gnu/softhsm", "/usr/lib/aarch64-linux-gnu/softhsm"},
				"darwin": {"/usr/local/opt/softhsm/lib/softhsm", "/opt/homebrew/opt/softhsm/lib/softhsm"},
			},
		},
		Catalog:  pkcs11.VendorCatalog{Level: pkcs11.CatalogStandardOnly, Source: "SoftHSM 2"},
		Behavior: pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, RejectNullOutputProbe: true},
		Conformance: pkcs11.VendorConformance{
			Provider: "softhsm2",
			Notes:    "Runs in the public SoftHSM 2 Testcontainers image",
		},
	})
}

// NewV3 returns the SoftHSM 3 module.
func NewV3() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: IDV3, Name: "SoftHSM 3", Priority: 72, Source: "SoftHSM",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"softhsm"}, Models: []string{"softhsm v3", "softhsm3"},
			ModulePaths: []string{"libsofthsm3", "softhsm3"}, MinimumTextMatches: 2,
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"SOFTHSM3_MODULE"},
			ModuleNames: map[string][]string{
				"linux": {"libsofthsm3.so"}, "darwin": {"libsofthsm3.dylib"}, "windows": {"softhsm3.dll"},
			},
		},
		Catalog:  pkcs11.VendorCatalog{Level: pkcs11.CatalogStandardOnly, Source: "SoftHSM 3"},
		Behavior: pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken},
		Conformance: pkcs11.VendorConformance{
			Notes: "Enable when a stable SoftHSM 3 build/runtime is supplied",
		},
	})
}

// All returns both supported SoftHSM generations.
func All() []pkcs11.VendorModule { return []pkcs11.VendorModule{NewV3(), NewV2()} }
