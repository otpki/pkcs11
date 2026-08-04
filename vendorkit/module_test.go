package vendorkit

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
)

func TestNewValidatesAndClonesDefinition(t *testing.T) {
	definition := pkcs11.VendorDefinition{
		ID:     "example-hsm",
		Name:   "Example HSM",
		Source: "example public SDK",
		Match: pkcs11.VendorMatchSpec{
			Manufacturers: []string{"Example"},
		},
		Discovery: pkcs11.VendorDiscovery{
			ModuleNames: map[string][]string{"linux": {"libexample.so"}},
		},
		Conformance: pkcs11.VendorConformance{
			Notes: "requires Example HSM hardware",
		},
	}

	module, err := New(definition)
	if err != nil {
		t.Fatal(err)
	}

	definition.Match.Manufacturers[0] = "mutated-input"
	first := module.Definition()
	if got := first.Match.Manufacturers[0]; got != "Example" {
		t.Fatalf("module retained caller-owned definition storage: %q", got)
	}

	first.Match.Manufacturers[0] = "mutated-output"
	second := module.Definition()
	if got := second.Match.Manufacturers[0]; got != "Example" {
		t.Fatalf("Definition returned mutable internal storage: %q", got)
	}
}

func TestNewRejectsIncompleteDefinition(t *testing.T) {
	if _, err := New(pkcs11.VendorDefinition{}); err == nil {
		t.Fatal("New accepted an empty definition")
	}
}

func TestDecorateRetainsBehaviorAndReplacesDefinition(t *testing.T) {
	base, err := New(pkcs11.VendorDefinition{
		ID: "example-hsm", Name: "Example HSM", Source: "public SDK",
		Match:       pkcs11.VendorMatchSpec{Manufacturers: []string{"Example"}},
		Discovery:   pkcs11.VendorDiscovery{ModuleNames: map[string][]string{"linux": {"libexample.so"}}},
		Conformance: pkcs11.VendorConformance{Notes: "requires hardware"},
	})
	if err != nil {
		t.Fatal(err)
	}

	decorated, err := Decorate(base, func(definition *pkcs11.VendorDefinition) {
		definition.Source = "licensed SDK 9.1"
		definition.Catalog.Mechanisms = map[string]pkcs11.NumericID{"example-operation": 0x80000001}
	})
	if err != nil {
		t.Fatal(err)
	}
	if decorated.VendorModule != base {
		t.Fatal("decorated module does not delegate to base")
	}
	definition := decorated.Definition()
	if definition.Source != "licensed SDK 9.1" || definition.Catalog.Mechanisms["example-operation"] != 0x80000001 {
		t.Fatalf("decorated definition = %#v", definition)
	}
}
