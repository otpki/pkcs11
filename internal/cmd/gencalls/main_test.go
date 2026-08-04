package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parsePinnedFunctions(t *testing.T) (string, []function) {
	t.Helper()
	root, err := findRepositoryRoot("")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, sourcePath))
	if err != nil {
		t.Fatal(err)
	}
	functions, err := parseFunctions(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return root, functions
}

func TestPinnedHeaderFunctionInventory(t *testing.T) {
	_, functions := parsePinnedFunctions(t)
	counts := map[tableVersion]int{}
	byName := make(map[string]function, len(functions))
	for _, function := range functions {
		counts[function.Version]++
		byName[function.Name] = function
	}
	if got, want := len(functions), 104; got != want {
		t.Fatalf("function count = %d, want %d", got, want)
	}
	if counts[versionBase] != 68 || counts[version30] != 24 || counts[version32] != 12 {
		t.Fatalf("version counts = %#v", counts)
	}
	checks := map[string]struct {
		version tableVersion
		args    int
	}{
		"C_Initialize":             {versionBase, 1},
		"C_OpenSession":            {versionBase, 5},
		"C_LoginUser":              {version30, 6},
		"C_EncryptMessageNext":     {version30, 8},
		"C_EncapsulateKey":         {version32, 8},
		"C_UnwrapKeyAuthenticated": {version32, 10},
	}
	for name, check := range checks {
		function, ok := byName[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if function.Version != check.version || len(function.Parameters) != check.args {
			t.Errorf("%s version/args = %v/%d, want %v/%d", name, function.Version, len(function.Parameters), check.version, check.args)
		}
	}
}

func TestRenderedBindingsAreCurrent(t *testing.T) {
	root, functions := parsePinnedFunctions(t)

	goGenerated, err := renderGo(functions)
	if err != nil {
		t.Fatal(err)
	}
	goCurrent, err := os.ReadFile(filepath.Join(root, goOutputPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goGenerated, goCurrent) {
		t.Fatalf("%s is stale; run go generate ./...", goOutputPath)
	}
	goText := string(goGenerated)
	for _, fragment := range []string{
		"arguments uint8",
		"const functionMaximumArguments = 10",
		`name: "C_Initialize"`,
		"arguments: 10",
	} {
		if !strings.Contains(goText, fragment) {
			t.Errorf("generated Go output does not contain %q", fragment)
		}
	}

	cgoGenerated := renderC(functions)
	cgoCurrent, err := os.ReadFile(filepath.Join(root, cOutputPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cgoGenerated, cgoCurrent) {
		t.Fatalf("%s is stale; run go generate ./...", cOutputPath)
	}
	cgoText := string(cgoGenerated)
	for _, fragment := range []string{
		"p11x_dispatch",
		"P11X_MAX_ARGUMENTS 10",
		"CK_FUNCTION_LIST_PTR f = p11x_base(ctx)",
		"CK_FUNCTION_LIST_3_0_PTR f = p11x_v3(ctx)",
		"CK_FUNCTION_LIST_3_2_PTR f = p11x_v32(ctx)",
		"f->C_UnwrapKeyAuthenticated",
	} {
		if !strings.Contains(cgoText, fragment) {
			t.Errorf("cgo generated output does not contain %q", fragment)
		}
	}
	if strings.Contains(cgoText, "static inline CK_RV p11x_C_") {
		t.Error("cgo output still contains redundant per-function wrapper definitions")
	}
}

func TestUnknownParameterTypeFails(t *testing.T) {
	_, err := parseParameters("(CK_UNKNOWN value);")
	if err == nil || !strings.Contains(err.Error(), "no parameter type mapping") {
		t.Fatalf("error = %v", err)
	}
}
