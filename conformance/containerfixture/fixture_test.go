package containerfixture

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestBasePrepare(t *testing.T) {
	root := t.TempDir()
	asset := filepath.Join(t.TempDir(), "client.zip")
	if err := os.WriteFile(asset, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := New(Definition{
		ID:           "example",
		Dockerfile:   "vendors/example/conformance/Dockerfile",
		Platform:     "linux/amd64",
		Timeout:      time.Minute,
		IncludeInAll: true,
		Assets:       []Asset{{Name: "client", Required: true}},
		Environment:  map[string]string{"DEFAULT": "value"},
	})
	prepared, err := fixture.Prepare(context.Background(), Request{
		RepositoryRoot: root,
		Assets:         map[string]string{"client": asset},
		Environment:    map[string]string{"OVERRIDE": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.BuildContext != root {
		t.Fatalf("BuildContext = %q, want %q", prepared.BuildContext, root)
	}
	if prepared.Dockerfile != "vendors/example/conformance/Dockerfile" {
		t.Fatalf("Dockerfile = %q", prepared.Dockerfile)
	}
	if prepared.Platform != "linux/amd64" {
		t.Fatalf("Platform = %q, want linux/amd64", prepared.Platform)
	}
	if !reflect.DeepEqual(prepared.Environment, map[string]string{"DEFAULT": "value", "OVERRIDE": "value"}) {
		t.Fatalf("Environment = %#v", prepared.Environment)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAssetsEnvironment(t *testing.T) {
	asset := filepath.Join(t.TempDir(), "runtime.zip")
	if err := os.WriteFile(asset, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_RUNTIME", asset)
	definition := Definition{
		ID: "example", Dockerfile: "Dockerfile", Timeout: time.Minute,
		Assets: []Asset{{Name: "runtime", Environment: "FIXTURE_RUNTIME", Required: true}},
	}
	resolved, err := ResolveAssets(definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved["runtime"] != asset {
		t.Fatalf("runtime = %q, want %q", resolved["runtime"], asset)
	}
}

func TestDefinitionsRejectDuplicateIDs(t *testing.T) {
	definition := Definition{ID: "same", Dockerfile: "Dockerfile", Timeout: time.Minute}
	if _, _, err := Definitions([]Fixture{New(definition), New(definition)}); err == nil {
		t.Fatal("expected duplicate fixture error")
	}
}

func TestDefinitionSnapshotsAreIndependent(t *testing.T) {
	fixture := New(Definition{
		ID: "example", Dockerfile: "Dockerfile", Timeout: time.Minute,
		Assets:      []Asset{{Name: "runtime"}},
		Environment: map[string]string{"KEY": "value"},
	})
	first := fixture.Definition()
	first.Assets[0].Name = "mutated"
	first.Environment["KEY"] = "mutated"
	second := fixture.Definition()
	if second.Assets[0].Name != "runtime" || second.Environment["KEY"] != "value" {
		t.Fatalf("fixture exposes mutable definition state: %#v", second)
	}
}

func TestValidatePlatform(t *testing.T) {
	definition, err := Validate(Definition{
		ID: "example", Dockerfile: "Dockerfile", Platform: " LINUX/AMD64 ", Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if definition.Platform != "linux/amd64" {
		t.Fatalf("Platform = %q, want linux/amd64", definition.Platform)
	}

	for _, platform := range []string{"linux", "/amd64", "linux/", "linux/amd64/"} {
		t.Run(platform, func(t *testing.T) {
			_, err := Validate(Definition{ID: "example", Dockerfile: "Dockerfile", Platform: platform, Timeout: time.Minute})
			if err == nil {
				t.Fatalf("expected invalid platform %q to fail", platform)
			}
		})
	}
}
