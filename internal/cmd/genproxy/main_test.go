package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseModuleSurface(t *testing.T) {
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	methods, err := parseMethods(filepath.Join(root, "raw", "module_interface.go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(methods), 113; got != want {
		t.Fatalf("raw.Module methods = %d, want %d", got, want)
	}
	byName := make(map[string]bool, len(methods))
	for _, method := range methods {
		if byName[method.Name] {
			t.Fatalf("duplicate method %q", method.Name)
		}
		byName[method.Name] = true
	}
	for _, name := range []string{"Initialize", "OpenSession", "Sign", "MessageSignInit", "EncapsulateKey", "WrapKeyAuthenticated"} {
		if !byName[name] {
			t.Fatalf("missing representative method %q", name)
		}
	}
}

func TestGeneratedClientIsCurrentAndDeterministic(t *testing.T) {
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "raw", "module_interface.go")
	parseAndRender := func() []byte {
		methods, err := parseMethods(input)
		if err != nil {
			t.Fatal(err)
		}
		output, err := renderClient(methods)
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	first := parseAndRender()
	second := parseAndRender()
	if !bytes.Equal(first, second) {
		t.Fatal("generated proxy client is not deterministic")
	}
	existing, err := os.ReadFile(filepath.Join(root, "proxy", "client_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, first) {
		t.Fatal("proxy/client_gen.go is stale; run go generate ./...")
	}
}
