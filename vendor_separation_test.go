package pkcs11

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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
