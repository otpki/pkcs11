package pkcs11

import "testing"

func TestVendorModuleValidationRejectsDuplicateIDs(t *testing.T) {
	first := newTestVendor("duplicate", "First", 1, VendorMatchSpec{Manufacturers: []string{"first"}})
	second := newTestVendor("duplicate", "Second", 1, VendorMatchSpec{Manufacturers: []string{"second"}})
	if _, _, err := validateVendorModules([]VendorModule{first, second}); err == nil {
		t.Fatal("expected duplicate module ID error")
	}
}

func TestVendorDefinitionIsClonedAndNormalized(t *testing.T) {
	module := newTestVendor(" Example-Vendor ", " Example Vendor ", 1, VendorMatchSpec{Manufacturers: []string{"example"}})
	module.definition.Discovery = VendorDiscovery{EnvironmentVariables: []string{"EXAMPLE_MODULE"}, ModuleNames: map[string][]string{"linux": {"libexample.so"}}}
	module.definition.Catalog = VendorCatalog{Source: " source ", Mechanisms: map[string]NumericID{" Example-Mechanism ": 0x80000001}}
	definition, err := normalizeVendorDefinition(module.Definition())
	if err != nil {
		t.Fatal(err)
	}
	if definition.ID != "example-vendor" || definition.Name != "Example Vendor" || definition.Catalog.Mechanisms["example-mechanism"] != 0x80000001 {
		t.Fatalf("normalized definition = %#v", definition)
	}
	definition.Discovery.ModuleNames["linux"][0] = "mutated"
	definition.Catalog.Mechanisms["example-mechanism"] = 2
	original := module.Definition()
	if original.Discovery.ModuleNames["linux"][0] != "libexample.so" || original.Catalog.Mechanisms[" Example-Mechanism "] != 0x80000001 {
		t.Fatal("normalization mutated module-owned definition")
	}
}

func TestVendorModulesReturnsGenericAndCandidateDiagnostics(t *testing.T) {
	module := newTestVendor("example", "Example", 1, VendorMatchSpec{Manufacturers: []string{"example"}})
	modules, err := VendorModules(module)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != 2 || modules[0].Family != "example" && modules[1].Family != "example" {
		t.Fatalf("diagnostics = %#v", modules)
	}
}
