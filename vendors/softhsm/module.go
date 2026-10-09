package softhsm

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendorkit"
)

const IDV2 pkcs11.AdapterFamily = "softhsm2"

type Module struct{ *vendorkit.Module }

// NewV2 returns the SoftHSM 2 module.
func NewV2() pkcs11.VendorModule {
	return &Module{vendorkit.MustNew(pkcs11.VendorDefinition{
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
	})}
}

// NormalizeTemplate drops CKA_PARAMETER_SET from generated private key
// templates. The spec says the mechanism picks the parameter set, and SoftHSM
// enforces that strictly. other providers need the attribute, so the route
// always sends it and we strip it back out for SoftHSM.
func (m *Module) NormalizeTemplate(context pkcs11.VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	if context.Operation == "C_GenerateKeyPair/private" {
		return pkcs11.RemoveAttributes(attributes, raw.CKA_PARAMETER_SET), nil
	}
	return m.VendorBase.NormalizeTemplate(context, attributes)
}

// All returns every supported SoftHSM module.
func All() []pkcs11.VendorModule { return []pkcs11.VendorModule{NewV2()} }
