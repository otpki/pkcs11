// Package vendortest contains reusable contract tests for VendorModule
// implementations, including providers maintained outside this repository.
package vendortest

import (
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// TB is the subset of testing.TB used by Module.
type TB interface {
	Helper()
	Errorf(string, ...any)
	Fatalf(string, ...any)
}

// Module verifies the static, concurrency-safe portion of the VendorModule
// contract. It does not require an HSM; live behavior belongs in provider-owned
// integration tests.
//
// The test checks definition validity, stable identity, immutable snapshots,
// discovery hygiene, catalog provenance, matchability, and conformance metadata.
// Call it from each provider package:
//
//	func TestModuleContract(t *testing.T) {
//		vendortest.Module(t, New())
//	}
func Module(t TB, module pkcs11.VendorModule) {
	t.Helper()
	if module == nil {
		t.Fatalf("VendorModule is nil")
	}
	if _, err := pkcs11.VendorModules(module); err != nil {
		t.Fatalf("VendorModule definition is invalid: %v", err)
	}

	first := module.Definition()
	second := module.Definition()
	if first.ID != second.ID || first.Name != second.Name || first.Priority != second.Priority {
		t.Errorf("Definition is not stable across calls: first=%#v second=%#v", first, second)
	}
	immutable := cloneDefinition(second)
	if strings.TrimSpace(first.Source) == "" && strings.TrimSpace(first.Catalog.Source) == "" {
		t.Errorf("vendor %q has no implementation provenance", first.ID)
	}
	checkConformanceMetadata(t, first)
	checkDiscovery(t, first)
	checkMatch(t, module, first)

	// Mutate a snapshot, then ask the module again. Modules are documented as
	// immutable and must not expose maps/slices whose mutation changes later
	// clients or races with concurrent discovery.
	mutated := first
	if len(mutated.Match.Manufacturers) != 0 {
		mutated.Match.Manufacturers[0] = "vendortest-mutated"
	}
	if len(mutated.Discovery.EnvironmentVariables) != 0 {
		mutated.Discovery.EnvironmentVariables[0] = "VENDORTEST_MUTATED"
	}
	for key, values := range mutated.Discovery.ModuleNames {
		if len(values) != 0 {
			values[0] = "vendortest-mutated"
			mutated.Discovery.ModuleNames[key] = values
			break
		}
	}
	for key := range mutated.Catalog.Mechanisms {
		mutated.Catalog.Mechanisms[key]++
		break
	}
	third := module.Definition()
	// Function values are intentionally not comparable through reflect.DeepEqual.
	immutable.MatchFunc = nil
	third.MatchFunc = nil
	if !reflect.DeepEqual(immutable, third) {
		t.Errorf("Definition exposes mutable shared state; before=%#v after=%#v", immutable, third)
	}

	// Definition is called from discovery, selection, diagnostics, and module
	// candidate enumeration. Exercise concurrent readers here; running the normal
	// provider suite with -race also verifies that the implementation has no
	// hidden lazy mutation.
	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			for range 64 {
				definition := module.Definition()
				if definition.ID != immutable.ID || definition.Name != immutable.Name {
					t.Errorf("Definition changed under concurrent access: %#v", definition)
					return
				}
			}
		})
	}
	wait.Wait()
}

func cloneDefinition(definition pkcs11.VendorDefinition) pkcs11.VendorDefinition {
	return pkcs11.CloneVendorDefinition(definition)
}

func checkConformanceMetadata(t TB, definition pkcs11.VendorDefinition) {
	t.Helper()
	if strings.TrimSpace(definition.Conformance.Provider) == "" && strings.TrimSpace(definition.Conformance.Notes) == "" {
		t.Errorf("vendor %q has neither a conformance provider nor external-runtime notes", definition.ID)
	}
}

func checkDiscovery(t TB, definition pkcs11.VendorDefinition) {
	t.Helper()
	for _, name := range definition.Discovery.EnvironmentVariables {
		if strings.TrimSpace(name) == "" {
			t.Errorf("vendor %q contains an empty discovery environment variable", definition.ID)
		}
	}
	for goos, names := range definition.Discovery.ModuleNames {
		for _, name := range names {
			if strings.TrimSpace(name) == "" {
				t.Errorf("vendor %q contains an empty %q module name", definition.ID, goos)
			}
			if filepath.Base(name) != name {
				t.Errorf("vendor %q module name %q must be a basename, not a path", definition.ID, name)
			}
		}
	}
	if len(definition.Discovery.EnvironmentVariables) == 0 && len(definition.Discovery.ModuleNames) == 0 {
		t.Errorf("vendor %q supplies no discovery environment variable or module name", definition.ID)
	}
}

func checkMatch(t TB, module pkcs11.VendorModule, definition pkcs11.VendorDefinition) {
	t.Helper()
	fingerprint := pkcs11.Fingerprint{
		ModulePath: firstDiscoveryName(definition.Discovery),
		Module: raw.Info{
			ManufacturerID:     first(definition.Match.Manufacturers, definition.Name),
			LibraryDescription: first(definition.Match.LibraryDescriptions, definition.Name),
		},
		Slot: raw.SlotInfo{
			ManufacturerID:  first(definition.Match.Manufacturers, definition.Name),
			SlotDescription: first(definition.Match.SlotDescriptions, definition.Name),
		},
		Token: raw.TokenInfo{
			ManufacturerID: first(definition.Match.Manufacturers, definition.Name),
			Model:          first(definition.Match.Models, definition.Name),
		},
		Mechanisms: make(map[raw.MechanismType]raw.MechanismInfo),
	}
	for _, mechanism := range definition.Match.RequiredMechanisms {
		fingerprint.Mechanisms[raw.MechanismType(mechanism)] = raw.MechanismInfo{}
	}
	match, err := pkcs11.MatchVendorModule(module, fingerprint)
	if err != nil {
		t.Errorf("vendor %q matcher failed: %v", definition.ID, err)
		return
	}
	if !match.Matched {
		t.Errorf("vendor %q did not recognize its synthesized fingerprint: %#v", definition.ID, fingerprint)
	}
}

func first(values []string, fallback string) string {
	if len(values) != 0 && strings.TrimSpace(values[0]) != "" {
		return values[0]
	}
	return fallback
}

func firstDiscoveryName(discovery pkcs11.VendorDiscovery) string {
	for _, names := range discovery.ModuleNames {
		if len(names) != 0 {
			return names[0]
		}
	}
	return "vendor-pkcs11-module"
}
