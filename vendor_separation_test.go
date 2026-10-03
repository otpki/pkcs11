package pkcs11

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// privateVendorPaths lists vendor source trees that live only in the optional
// pkcs11-private-vendors module. They must never exist as public source.
var privateVendorPaths = []string{
	"vendors/utimaco",
	"vendors/securosys",
	"vendors/nshield",
	"vendors/thales",
	"vendors/crypto4a",
	"vendors/ibm",
	"vendors/fortanix",
}

// TestRootPackageHasNoConcreteVendorImports locks the architectural boundary:
// the root driver may depend on VendorModule, but it must never import a
// provider implementation. A new provider therefore cannot require editing a
// root import switch or introduce an import cycle for out-of-tree modules.
func TestRootPackageHasNoConcreteVendorImports(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(files, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("parse import in %s: %v", path, err)
			}
			if strings.Contains(name, "/vendors/") || strings.Contains(name, "/internal/hsmvendor/") {
				t.Errorf("root file %s imports concrete vendor package %q", path, name)
			}
		}
	}
}

// Build tags cannot hide private imports from go mod tidy. Scan source imports
// regardless of tags, including examples and nested public modules.
func TestPublicTreeHasNoPrivateVendorDependency(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// The optional submodule is its own Go module. Do not scan its
			// private imports as though they belonged to the public module.
			if filepath.ToSlash(path) == "pkcs11-private-vendors" {
				return filepath.SkipDir
			}
			if path != "." && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "licensed") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == "go.mod" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "pkcs11-private-vendors") {
				t.Errorf("private dependency in %s", path)
			}
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if strings.Contains(name, "pkcs11-private-vendors") {
				t.Errorf("public source %s imports private vendor package %s", path, name)
			}
			for _, privateVendor := range privateVendorPaths {
				if strings.HasPrefix(name, "github.com/otpki/pkcs11/"+privateVendor) {
					t.Errorf("public source %s imports private vendor package %s", path, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range privateVendorPaths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("unexpected private source or submodule path: %s", path)
		}
	}
}

// Reject accidental source copies tracked inside the PUBLIC repository. A
// registered submodule has exactly one mode-160000 entry, never source files.
func TestPrivateSourceIsOnlyAnOptionalGitlink(t *testing.T) {
	data, err := os.ReadFile(".gitmodules")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`[submodule "pkcs11-private-vendors"]`,
		"path = pkcs11-private-vendors",
		"url = https://github.com/otpki/pkcs11-private-vendors.git",
	} {
		if !strings.Contains(string(data), required) {
			t.Errorf(".gitmodules lacks %q", required)
		}
	}
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		t.Log("source archive: no Git index to inspect")
		return
	}
	out, err := exec.Command("git", "ls-files", "--stage", "--", "pkcs11-private-vendors").Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		} // Pre-bootstrap public split is allowed.
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] != "160000" || fields[2] != "0" || fields[3] != "pkcs11-private-vendors" {
			t.Error("private source is tracked as public files instead of a single Git submodule")
		}
	}
}
