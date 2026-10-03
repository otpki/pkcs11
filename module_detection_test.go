package pkcs11

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestModuleCandidatesUseOnlySuppliedVendorDiscovery proves that the root
// package does not carry an implicit provider filename catalog. A vendor-shaped
// library in a searched directory is invisible until the caller supplies the
// VendorModule that owns that basename.
func TestModuleCandidatesUseOnlySuppliedVendorDiscovery(t *testing.T) {
	directory := t.TempDir()
	name := platformTestModuleName("acme")
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("not a real shared library"), 0o600); err != nil {
		t.Fatal(err)
	}

	config := DetectionConfig{
		SearchDirectories: directoryList(directory),
	}
	withoutVendor, err := ModuleCandidates(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutVendor) != 0 {
		t.Fatalf("standards-only discovery unexpectedly found %#v", withoutVendor)
	}

	module := discoveryTestVendor(name, "ACME_PKCS11_MODULE")
	withVendor, err := ModuleCandidates(config, module)
	if err != nil {
		t.Fatal(err)
	}
	if len(withVendor) != 1 {
		t.Fatalf("vendor discovery returned %d candidates, want 1: %#v", len(withVendor), withVendor)
	}
	candidate := withVendor[0]

	// ModuleCandidates canonicalizes existing paths with filepath.EvalSymlinks.
	// On macOS, t.TempDir commonly returns a path below /var, while /var is a
	// symlink to /private/var. Compare file identity rather than the textual path
	// so the test accepts both spellings of the same native library.
	expectedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	candidateInfo, err := os.Stat(candidate.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(candidateInfo, expectedInfo) {
		t.Fatalf("candidate path = %q, want the same file as %q", candidate.Path, path)
	}
	if candidate.Family != module.Definition().ID {
		t.Fatalf("candidate family = %q, want %q", candidate.Family, module.Definition().ID)
	}
	if candidate.Source != "vendor-discovery:"+string(module.Definition().ID) {
		t.Fatalf("candidate source = %q", candidate.Source)
	}
}

// TestModuleCandidatesUseVendorEnvironmentHints verifies that provider-specific
// environment variables are data owned by the supplied module rather than
// globally recognized names in the driver.
func TestModuleCandidatesUseVendorEnvironmentHints(t *testing.T) {
	path := filepath.Join(t.TempDir(), platformTestModuleName("acme-env"))
	if err := os.WriteFile(path, []byte("not a real shared library"), 0o600); err != nil {
		t.Fatal(err)
	}
	const variable = "ACME_TEST_PKCS11_MODULE"
	t.Setenv(variable, path)

	config := DetectionConfig{IncludeEnvironment: true}
	withoutVendor, err := ModuleCandidates(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutVendor) != 0 {
		t.Fatalf("provider-specific environment variable leaked into core discovery: %#v", withoutVendor)
	}

	module := discoveryTestVendor(filepath.Base(path), variable)
	withVendor, err := ModuleCandidates(config, module)
	if err != nil {
		t.Fatal(err)
	}
	if len(withVendor) != 1 {
		t.Fatalf("environment discovery returned %d candidates, want 1: %#v", len(withVendor), withVendor)
	}
	if withVendor[0].Family != module.Definition().ID || withVendor[0].Source != "env:"+variable {
		t.Fatalf("environment candidate = %#v", withVendor[0])
	}
}

// TestModuleCandidatesPreserveFirstSource verifies deterministic precedence and
// deduplication. An explicit path wins over the same path contributed later by
// a provider environment variable or directory hint.
func TestModuleCandidatesPreserveFirstSource(t *testing.T) {
	directory := t.TempDir()
	name := platformTestModuleName("acme-order")
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("not a real shared library"), 0o600); err != nil {
		t.Fatal(err)
	}
	const variable = "ACME_TEST_PKCS11_ORDER_MODULE"
	t.Setenv(variable, path)
	module := discoveryTestVendor(name, variable)

	candidates, err := ModuleCandidates(DetectionConfig{
		ExplicitPaths:      []string{path},
		SearchDirectories:  directoryList(directory),
		IncludeEnvironment: true,
	}, module)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("deduplicated candidates = %#v", candidates)
	}
	if candidates[0].Source != "explicit" || candidates[0].Family != "" {
		t.Fatalf("first candidate metadata was replaced: %#v", candidates[0])
	}
}

func discoveryTestVendor(moduleName, environmentVariable string) *testVendorModule {
	module := newTestVendor("acme-test-hsm", "Acme Test HSM", 1, VendorMatchSpec{
		Manufacturers: []string{"acme"},
	})
	module.definition.Discovery = VendorDiscovery{
		EnvironmentVariables: []string{environmentVariable},
		ModuleNames: map[string][]string{
			runtime.GOOS: {moduleName},
		},
	}
	return module
}

func platformTestModuleName(stem string) string {
	switch runtime.GOOS {
	case "windows":
		return stem + ".dll"
	case "darwin":
		return "lib" + stem + ".dylib"
	default:
		return "lib" + stem + ".so"
	}
}

func directoryList(directory string) []string { return []string{directory} }
