package raw

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiteralNativeCallsMatchPinnedSignatures statically checks every direct
// c.call(functionX, ...) expression. Helpers whose function ID is passed as a
// variable are covered by their own runtime paths and the generated argument
// metadata, while literal calls are checked here before they can reach native
// code with the wrong register/stack shape.
func TestLiteralNativeCallsMatchPinnedSignatures(t *testing.T) {
	ids := make(map[string]functionID, functionCount)
	for id := range functionCount {
		ids["function"+strings.TrimPrefix(functionTableMetadata[id].name, "C_")] = id
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || path == "function_table_gen.go" {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "call" || len(call.Args) == 0 {
				return true
			}
			identifier, ok := call.Args[0].(*ast.Ident)
			if !ok {
				return true
			}
			id, ok := ids[identifier.Name]
			if !ok {
				return true
			}
			checked++
			got := len(call.Args) - 1
			want := int(functionTableMetadata[id].arguments)
			if got != want {
				position := fset.Position(call.Pos())
				t.Errorf("%s:%d: %s has %d native arguments, want %d", path, position.Line, identifier.Name, got, want)
			}
			return true
		})
	}
	if checked < 60 {
		t.Fatalf("checked only %d literal native calls; expected broad binding coverage", checked)
	}
}

// TestEveryGeneratedFunctionIsReferencedBySharedCode ensures that the OASIS
// function inventory and the shared semantic implementation cannot drift apart.
// A function may be dispatched through a helper that accepts a functionID, so
// this test tracks identifier use rather than requiring every call site to use
// a literal c.call expression.
func TestEveryGeneratedFunctionIsReferencedBySharedCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	referenced := make(map[string]bool, functionCount)
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || path == "function_table_gen.go" {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && strings.HasPrefix(identifier.Name, "function") {
				referenced[identifier.Name] = true
			}
			return true
		})
	}

	for id := range functionCount {
		name := "function" + strings.TrimPrefix(functionTableMetadata[id].name, "C_")
		if !referenced[name] {
			t.Errorf("generated function %s (%s) is not referenced by shared raw code", name, functionTableMetadata[id].name)
		}
	}
}
