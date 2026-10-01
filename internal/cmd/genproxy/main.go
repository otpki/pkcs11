package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

var check = flag.Bool("check", false, "verify generated output")

func main() {
	flag.Parse()
	root, err := findRoot()
	if err != nil {
		fatal(err)
	}
	methods, err := parseMethods(filepath.Join(root, "raw", "module_interface.go"))
	if err != nil {
		fatal(err)
	}
	output, err := renderClient(methods)
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(root, "proxy", "client_gen.go")
	if *check {
		existing, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		if !bytes.Equal(existing, output) {
			fatal(fmt.Errorf("%s is stale; run 'go generate ./...'", path))
		}
		return
	}
	if err := os.WriteFile(path, output, 0o644); err != nil {
		fatal(err)
	}
}

func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

type method struct {
	Name            string
	Params, Results *ast.FieldList
}

func parseMethods(path string) ([]method, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Module" {
				continue
			}
			iface, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				return nil, errors.New("module declaration is not an interface")
			}
			var methods []method
			for _, field := range iface.Methods.List {
				if len(field.Names) != 1 {
					continue
				}
				fn, ok := field.Type.(*ast.FuncType)
				if !ok {
					continue
				}
				methods = append(methods, method{Name: field.Names[0].Name, Params: fn.Params, Results: fn.Results})
			}
			return methods, nil
		}
	}
	return nil, errors.New("raw.Module not found")
}

var predeclaredTypes = map[string]struct{}{
	"any": {}, "bool": {}, "byte": {}, "complex128": {}, "complex64": {},
	"error": {}, "float32": {}, "float64": {}, "int": {}, "int16": {},
	"int32": {}, "int64": {}, "int8": {}, "rune": {}, "string": {},
	"uint": {}, "uint16": {}, "uint32": {}, "uint64": {}, "uint8": {},
	"uintptr": {},
}

// qualifyRawTypes rewrites type identifiers declared by package raw into
// explicit raw.Name selectors. The generator intentionally avoids a dot import:
// a future raw package function can otherwise collide with a proxy declaration
// even when the generated method surface itself has not changed.
func qualifyRawTypes(expression ast.Expr) ast.Expr {
	switch value := expression.(type) {
	case *ast.Ident:
		if _, ok := predeclaredTypes[value.Name]; ok {
			return value
		}
		return &ast.SelectorExpr{X: ast.NewIdent("raw"), Sel: ast.NewIdent(value.Name)}
	case *ast.StarExpr:
		value.X = qualifyRawTypes(value.X)
	case *ast.ArrayType:
		value.Elt = qualifyRawTypes(value.Elt)
	case *ast.MapType:
		value.Key = qualifyRawTypes(value.Key)
		value.Value = qualifyRawTypes(value.Value)
	case *ast.ChanType:
		value.Value = qualifyRawTypes(value.Value)
	case *ast.Ellipsis:
		value.Elt = qualifyRawTypes(value.Elt)
	case *ast.FuncType:
		qualifyFieldList(value.Params)
		qualifyFieldList(value.Results)
	case *ast.InterfaceType:
		qualifyFieldList(value.Methods)
	case *ast.StructType:
		qualifyFieldList(value.Fields)
	case *ast.ParenExpr:
		value.X = qualifyRawTypes(value.X)
	case *ast.IndexExpr:
		value.X = qualifyRawTypes(value.X)
		value.Index = qualifyRawTypes(value.Index)
	case *ast.IndexListExpr:
		value.X = qualifyRawTypes(value.X)
		for index := range value.Indices {
			value.Indices[index] = qualifyRawTypes(value.Indices[index])
		}
	case *ast.SelectorExpr:
		// Selectors are already qualified (for example context.Context).
		return value
	}
	return expression
}

func qualifyFieldList(list *ast.FieldList) {
	if list == nil {
		return
	}
	for _, field := range list.List {
		field.Type = qualifyRawTypes(field.Type)
	}
}

func expression(node ast.Node) string {
	if typed, ok := node.(ast.Expr); ok {
		node = qualifyRawTypes(typed)
	}
	var buffer bytes.Buffer
	_ = printer.Fprint(&buffer, token.NewFileSet(), node)
	return buffer.String()
}

func fields(list *ast.FieldList) (declaration string, names []string) {
	if list == nil {
		return "", nil
	}
	var parts []string
	for _, field := range list.List {
		typ := expression(field.Type)
		if len(field.Names) == 0 {
			parts = append(parts, typ)
			continue
		}
		var group []string
		for _, name := range field.Names {
			group = append(group, name.Name)
			names = append(names, name.Name)
		}
		parts = append(parts, strings.Join(group, ", ")+" "+typ)
	}
	return strings.Join(parts, ", "), names
}

func resultSignature(list *ast.FieldList) string {
	if list == nil || len(list.List) == 0 {
		return ""
	}
	decl, _ := fields(list)
	if len(list.List) == 1 && len(list.List[0].Names) == 0 {
		return " " + decl
	}
	return " (" + decl + ")"
}

func renderClient(methods []method) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("// Code generated by internal/cmd/genproxy; DO NOT EDIT.\n\npackage proxy\n\nimport raw \"github.com/otpki/pkcs11/raw\"\n\n")
	skip := map[string]bool{"Path": true, "Interface": true, "Version": true, "Supports": true, "Destroy": true}
	for _, method := range methods {
		if skip[method.Name] {
			continue
		}
		params, names := fields(method.Params)
		fmt.Fprintf(&out, "// %s forwards raw.Module.%s over one bounded proxy request.\n", method.Name, method.Name)
		fmt.Fprintf(&out, "func (c *Client) %s(%s)%s {\n", method.Name, params, resultSignature(method.Results))
		args := "nil"
		if len(names) > 0 {
			args = "[]any{" + strings.Join(names, ", ") + "}"
		}
		resultTypes := []string{}
		if method.Results != nil {
			for _, field := range method.Results.List {
				resultTypes = append(resultTypes, expression(field.Type))
			}
		}
		switch {
		case len(resultTypes) == 0:
			fmt.Fprintf(&out, "\t_ = c.invoke(%q, %s)\n", method.Name, args)
		case len(resultTypes) == 1 && resultTypes[0] == "error":
			fmt.Fprintf(&out, "\treturn c.invoke(%q, %s)\n", method.Name, args)
		default:
			valueCount := len(resultTypes)
			if resultTypes[valueCount-1] == "error" {
				valueCount--
			}
			var dest []string
			for i := 0; i < valueCount; i++ {
				fmt.Fprintf(&out, "\tvar result%d %s\n", i, resultTypes[i])
				dest = append(dest, fmt.Sprintf("&result%d", i))
			}
			fmt.Fprintf(&out, "\terr := c.invoke(%q, %s", method.Name, args)
			if len(dest) > 0 {
				fmt.Fprintf(&out, ", %s", strings.Join(dest, ", "))
			}
			out.WriteString(")\n\treturn ")
			var returns []string
			for i := 0; i < valueCount; i++ {
				returns = append(returns, fmt.Sprintf("result%d", i))
			}
			returns = append(returns, "err")
			fmt.Fprintf(&out, "%s\n", strings.Join(returns, ", "))
		}
		out.WriteString("}\n\n")
	}
	return format.Source(out.Bytes())
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "genproxy:", err); os.Exit(1) }
