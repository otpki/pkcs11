// Package azure provides the Azure Managed HSM PKCS #11 vendor module.
package azure

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
)

// ID is the stable VendorModule identifier for Azure Managed HSM.
const ID pkcs11.AdapterFamily = "azure-managed-hsm"

// New constructs the Azure Managed HSM vendor module.
func New() pkcs11.VendorModule {
	return vendorkit.MustNew(pkcs11.VendorDefinition{
		ID: ID, Name: "Azure Managed HSM PKCS #11", Priority: 92, Source: "Azure Managed HSM client metadata",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"microsoft", "marvell"}, LibraryDescriptions: []string{"azure", "managed hsm"}, Models: []string{"managed hsm"}, ModulePaths: []string{"azure", "managedhsm"}},
		Discovery:   pkcs11.VendorDiscovery{EnvironmentVariables: []string{"AZURE_MANAGED_HSM_PKCS11_MODULE"}},
		Catalog:     pkcs11.VendorCatalog{Level: pkcs11.CatalogVendorSDKRequired, Source: "Azure client SDK required for unpublished extensions"},
		Behavior:    pkcs11.VendorBehavior{LoginScope: pkcs11.VendorLoginToken, NetworkBacked: true},
		Conformance: pkcs11.VendorConformance{Notes: "Requires Azure Managed HSM access and client middleware"},
	})
}
