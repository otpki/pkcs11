// Package thales provides vendor modules for Luna/DPoD and ProtectServer.
package thales

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

const (
	// IDLuna is the stable VendorModule identifier for Luna and DPoD.
	IDLuna pkcs11.AdapterFamily = "thales-luna"
	// IDProtectServer is the stable VendorModule identifier for ProtectServer.
	IDProtectServer pkcs11.AdapterFamily = "thales-protectserver"

	// MechanismExternalMuMLDSA is Luna's public external-mu ML-DSA mechanism.
	MechanismExternalMuMLDSA uint = 0x80000175
)

// NewLuna returns the Luna/DPoD module.
func NewLuna() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: IDLuna, Name: "Thales Luna / DPoD", Priority: 105,
		Source: "Thales Luna SDK documentation",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers:       []string{"thales", "safenet", "gemalto"},
			LibraryDescriptions: []string{"chrystoki", "luna", "dpod"},
			Models:              []string{"luna", "dpod"}, ModulePaths: []string{"cryptoki2", "lunaclient"},
			MinimumTextMatches: 2,
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"LUNA_PKCS11_MODULE", "CHRYSTOKI_LIBRARY"},
			ModuleNames: map[string][]string{
				"linux":  {"libCryptoki2_64.so", "libCryptoki2.so"},
				"darwin": {"libCryptoki2.dylib"}, "windows": {"cryptoki.dll"},
			},
			SearchDirectories: map[string][]string{"linux": {"/usr/safenet/lunaclient/lib"}},
		},
		Catalog: pkcs11.VendorCatalog{
			Level: pkcs11.CatalogPublic, Source: "Thales Luna SDK documentation",
			Mechanisms: map[string]pkcs11.NumericID{
				"ml-dsa-external-mu":        NumericID(MechanismExternalMuMLDSA),
				"thales-ml-dsa-external-mu": NumericID(MechanismExternalMuMLDSA),
			},
		},
		Behavior: pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires Luna Client and a partition or DPoD service",
		},
	})
}

// NewProtectServer returns the ProtectServer/ProtectToolkit module.
func NewProtectServer() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: IDProtectServer, Name: "Thales ProtectServer", Priority: 108,
		Source: "Thales ProtectToolkit metadata",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers:       []string{"thales", "safenet", "gemalto"},
			LibraryDescriptions: []string{"protectserver", "protect toolkit"},
			Models:              []string{"protectserver"}, ModulePaths: []string{"protectserver", "protecttoolkit", "/ptk/"},
			MinimumTextMatches: 2,
		},
		Discovery: pkcs11.VendorDiscovery{
			EnvironmentVariables: []string{"PROTECTSERVER_PKCS11_MODULE"},
			ModuleNames: map[string][]string{
				"linux": {"libcryptoki.so"}, "darwin": {"libcryptoki.dylib"}, "windows": {"cryptoki.dll"},
			},
		},
		Catalog:  pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "ProtectToolkit SDK required for unpublished extensions"},
		Behavior: pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken},
		Conformance: pkcs11.VendorConformance{
			Notes: "Requires ProtectToolkit and ProtectServer access",
		},
	})
}

// All returns every Thales module provided by this package.
func All() []pkcs11.VendorModule { return []pkcs11.VendorModule{NewProtectServer(), NewLuna()} }

// NumericID avoids repetitive conversions in catalog literals.
func NumericID(value uint) pkcs11.NumericID { return pkcs11.NumericID(value) }
