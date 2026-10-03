package proxycmd

import (
	"bytes"
	"strings"
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
)

type testExtension struct{ pkcs11.VendorBase }

func (*testExtension) Definition() pkcs11.VendorDefinition {
	return pkcs11.VendorDefinition{ID: "test-extension", Name: "Test Extension"}
}

func TestCommandVendorInjectionIsLocal(t *testing.T) {
	supplied := []pkcs11.VendorModule{&testExtension{}}
	custom := New(Options{Version: "test-version", Vendors: supplied})
	supplied[0] = nil // New must copy the slice, not retain caller storage.
	var out bytes.Buffer
	custom.SetOut(&out)
	custom.SetArgs([]string{"vendors"})
	if err := custom.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "test-extension\tTest Extension") {
		t.Fatal(out.String())
	}
	if custom.Version != "test-version" {
		t.Fatal(custom.Version)
	}

	out.Reset()
	ordinary := New(Options{})
	ordinary.SetOut(&out)
	ordinary.SetArgs([]string{"vendors"})
	if err := ordinary.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "test-extension") {
		t.Fatal("vendor registration leaked between commands")
	}
}

func TestExplicitEmptyVendorsMeansStandardsOnly(t *testing.T) {
	cmd := New(Options{Vendors: []pkcs11.VendorModule{}})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"vendors"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal(out.String())
	}
}

func TestTargetConfigUsesInjectedVendorSet(t *testing.T) {
	cfg, err := loadOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.bundledVendors = []pkcs11.VendorModule{&testExtension{}}
	target, err := cfg.targetConfig(targetSpec{
		Name: "extension", Module: "test", Vendors: []string{"test-extension"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Client.Vendors) != 1 || target.Client.Vendors[0].Definition().ID != "test-extension" {
		t.Fatal("target did not receive injected vendor")
	}
	if _, err := cfg.targetConfig(targetSpec{
		Name: "other", Module: "test", Vendors: []string{"missing-extension"},
	}); err == nil {
		t.Fatal("unknown requested vendor accepted")
	}
}
