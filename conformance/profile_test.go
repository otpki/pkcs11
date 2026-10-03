package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestProfileRejectsDuplicateCases(t *testing.T) {
	profile := Profile{
		Cases: []Case{
			{Name: "same", Kind: "runtime"},
			{Name: "same", Kind: "random"},
		},
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("expected duplicate case error")
	}
}

func TestProfileRejectsUnknownEnabledCaseKind(t *testing.T) {
	profile := Profile{
		Cases: []Case{{
			Name:        "future",
			Kind:        "future-operation",
			Requirement: Required,
		}},
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("expected unknown enabled case kind to fail validation")
	}
	profile.Cases[0].Requirement = Disabled
	if err := profile.Validate(); err != nil {
		t.Fatalf("disabled placeholder should be valid: %v", err)
	}
}

type conformanceTestModuleSource struct{}

func (conformanceTestModuleSource) OpenModule(context.Context) (raw.Module, error) {
	return nil, errors.New("not opened by configuration test")
}
func (conformanceTestModuleSource) RegistryKey() string { return "test:remote" }
func (conformanceTestModuleSource) String() string      { return "test remote module" }

func TestClientConfigMayUseModuleSourceOverride(t *testing.T) {
	profile := Profile{Cases: []Case{{Name: "runtime", Kind: "runtime"}}}
	source := conformanceTestModuleSource{}
	config, err := profile.clientConfig(nil, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := config.Module.(conformanceTestModuleSource); !ok {
		t.Fatalf("module source type = %T, want conformanceTestModuleSource", config.Module)
	}
	resolved, _, err := resolveRunConfig([]RunOption{WithModuleSource(source)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolved.module.(conformanceTestModuleSource); !ok {
		t.Fatalf("run option module type = %T, want conformanceTestModuleSource", resolved.module)
	}
}
