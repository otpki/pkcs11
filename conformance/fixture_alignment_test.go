package conformance_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/otpki/pkcs11/conformance/containerfixture"
	vendorall "github.com/otpki/pkcs11/vendors/all"
	vendorconformance "github.com/otpki/pkcs11/vendors/conformance/all"
)

func TestEveryLiveVendorProviderHasAContainerFixture(t *testing.T) {
	_, definitions, err := containerfixture.Definitions(vendorconformance.Fixtures())
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range vendorall.Modules() {
		definition := module.Definition()
		if definition.Conformance.Provider == "" {
			continue
		}
		fixture, ok := definitions[definition.Conformance.Provider]
		if !ok {
			t.Errorf("live vendor %q names missing container fixture %q", definition.ID, definition.Conformance.Provider)
			continue
		}
		if fixture.Dockerfile == "" || fixture.Timeout <= 0 {
			t.Errorf("live vendor %q has incomplete fixture %#v", definition.ID, fixture)
		}
	}
}

func TestDockerfilesRemainLegacyBuilderCompatible(t *testing.T) {
	root := filepath.Join("..", "vendors")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "Dockerfile") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, unsupported := range []string{"# syntax=", "COPY --chmod", "RUN --mount"} {
			if strings.Contains(text, unsupported) {
				t.Errorf("%s uses BuildKit-only syntax %q", path, unsupported)
			}
		}
		if strings.Contains(text, "run-go-tests.sh") && !strings.Contains(text, "chmod 0755") {
			t.Errorf("%s does not set executable permissions explicitly", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDockerContextExcludesLocalState(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	patterns := strings.Fields(string(data))
	for _, required := range []string{".git", ".idea", "reports"} {
		found := slices.Contains(patterns, required)
		if !found {
			t.Errorf(".dockerignore is missing %q", required)
		}
	}
	for _, pattern := range patterns {
		if pattern == "licensed" || pattern == "licensed/" {
			t.Fatal(".dockerignore must not exclude prepared licensed fixture assets")
		}
	}
}
