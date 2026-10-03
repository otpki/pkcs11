package raw

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRawOperationsAreImplementedOnce ensures that the code is easy to maintain
// and that implementations do not cross the CGO/purego boundary
// Cryptoki semantics live in ordinary shared Go files,
// while build-selected files are limited to loading, native allocation, and
// function-pointer invocation.
func TestRawOperationsAreImplementedOnce(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	sharedOperations := map[string]bool{
		"module.go": false, "info.go": false, "session.go": false,
		"object.go": false, "crypto.go": false, "key.go": false,
		"message.go": false, "v32.go": false, "marshal.go": false,
		"active_mechanisms.go": false,
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		constraint := firstBuildConstraint(data)

		if _, ok := sharedOperations[name]; ok {
			sharedOperations[name] = true
			if constraint != "" {
				t.Errorf("shared operation file %s has backend build constraint %q", name, constraint)
			}
		}

		backendSpecific := strings.Contains(constraint, "cgo") || strings.Contains(constraint, "pkcs11_purego")
		if !backendSpecific {
			if strings.HasSuffix(name, "_cgo.go") || strings.HasSuffix(name, "_purego.go") {
				t.Errorf("semantic backend duplication reintroduced in %s", name)
			}
			continue
		}
		if !strings.HasPrefix(name, "native_") {
			t.Errorf("backend-selected production file %s must be a narrow native transport", name)
		}

		file, err := parser.ParseFile(token.NewFileSet(), name, data, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if value.Recv != nil {
					for _, field := range value.Recv.List {
						if receiverNamesCtx(field.Type) {
							t.Errorf("backend transport file %s defines Ctx method %s; move Cryptoki semantics to shared code", name, value.Name.Name)
						}
					}
				}
				if value.Name.IsExported() && value.Name.Name != "NativeAvailable" {
					t.Errorf("backend transport file %s exports function %s", name, value.Name.Name)
				}
			case *ast.GenDecl:
				for _, specification := range value.Specs {
					switch specification := specification.(type) {
					case *ast.TypeSpec:
						if specification.Name.IsExported() {
							t.Errorf("backend transport file %s exports type %s", name, specification.Name.Name)
						}
					case *ast.ValueSpec:
						for _, identifier := range specification.Names {
							if identifier.IsExported() {
								t.Errorf("backend transport file %s exports value %s", name, identifier.Name)
							}
						}
					}
				}
			}
		}
	}

	for name, found := range sharedOperations {
		if !found {
			t.Errorf("shared operation file %s is missing", name)
		}
	}
}

func firstBuildConstraint(data []byte) string {
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") {
			return line
		}
		if line != "" && !strings.HasPrefix(line, "//") {
			return ""
		}
	}
	return ""
}

func receiverNamesCtx(expression ast.Expr) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name == "Ctx"
	case *ast.StarExpr:
		return receiverNamesCtx(value.X)
	case *ast.IndexExpr:
		return receiverNamesCtx(value.X)
	case *ast.IndexListExpr:
		return receiverNamesCtx(value.X)
	case *ast.SelectorExpr:
		return value.Sel.Name == "Ctx"
	default:
		return false
	}
}

func TestGeneratedFunctionMetadataIsBackendNeutral(t *testing.T) {
	path := filepath.Clean("function_table_gen.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if constraint := firstBuildConstraint(data); constraint != "" {
		t.Fatalf("%s has backend build constraint %q", path, constraint)
	}
	if got := len(functionTableMetadata); got != 104 {
		t.Fatalf("function metadata count = %d, want 104", got)
	}
}
