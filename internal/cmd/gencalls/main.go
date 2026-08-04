// Command gencalls generates the shared PKCS #11 function inventory and the
// cgo transport's generic typed dispatcher.
//
// The authoritative function names, order, parameter declarations, and version
// boundaries come from the pinned OASIS pkcs11f.h header. The generator does
// not maintain a second list of Cryptoki functions.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	sourcePath               = "raw/internal/cryptoki/oasis/3.2/pkcs11f.h"
	goOutputPath             = "raw/function_table_gen.go"
	cOutputPath              = "raw/internal/cryptoki/calls_gen.h"
	maximumDispatchArguments = 10
)

type tableVersion uint8

const (
	versionBase tableVersion = iota
	version30
	version32
)

type parameter struct {
	Declaration string
	Name        string
}

type function struct {
	Name       string
	Version    tableVersion
	Parameters []parameter
}

// parameterTypes validates every OASIS parameter declaration while parsing and
// gives the generated C dispatcher the concrete type needed for each uintptr_t
// argument. Retaining the complete map makes a header update fail loudly when
// a new ABI form appears rather than silently changing the binding surface.
var parameterTypes = map[string]string{
	"CK_ASYNC_DATA_PTR":                "CK_ASYNC_DATA *",
	"CK_ATTRIBUTE_PTR":                 "CK_ATTRIBUTE *",
	"CK_BBOOL":                         "unsigned char",
	"CK_BYTE_PTR":                      "unsigned char *",
	"CK_FLAGS":                         "CK_FLAGS",
	"CK_FLAGS_PTR":                     "CK_FLAGS *",
	"CK_FUNCTION_LIST_PTR_PTR":         "CK_FUNCTION_LIST **",
	"CK_INFO_PTR":                      "CK_INFO *",
	"CK_INTERFACE_PTR":                 "struct CK_INTERFACE *",
	"CK_INTERFACE_PTR_PTR":             "struct CK_INTERFACE **",
	"CK_MECHANISM_INFO_PTR":            "CK_MECHANISM_INFO *",
	"CK_MECHANISM_PTR":                 "CK_MECHANISM *",
	"CK_MECHANISM_TYPE":                "CK_MECHANISM_TYPE",
	"CK_MECHANISM_TYPE_PTR":            "CK_MECHANISM_TYPE *",
	"CK_NOTIFY":                        "CK_NOTIFY",
	"CK_OBJECT_HANDLE":                 "CK_OBJECT_HANDLE",
	"CK_OBJECT_HANDLE_PTR":             "CK_OBJECT_HANDLE *",
	"CK_SESSION_HANDLE":                "CK_SESSION_HANDLE",
	"CK_SESSION_HANDLE_PTR":            "CK_SESSION_HANDLE *",
	"CK_SESSION_INFO_PTR":              "CK_SESSION_INFO *",
	"CK_SESSION_VALIDATION_FLAGS_TYPE": "CK_SESSION_VALIDATION_FLAGS_TYPE",
	"CK_SLOT_ID":                       "CK_SLOT_ID",
	"CK_SLOT_ID_PTR":                   "CK_SLOT_ID *",
	"CK_SLOT_INFO_PTR":                 "CK_SLOT_INFO *",
	"CK_TOKEN_INFO_PTR":                "CK_TOKEN_INFO *",
	"CK_ULONG":                         "unsigned long",
	"CK_ULONG_PTR":                     "unsigned long *",
	"CK_USER_TYPE":                     "CK_USER_TYPE",
	"CK_UTF8CHAR_PTR":                  "unsigned char *",
	"CK_VERSION_PTR":                   "CK_VERSION *",
	"CK_VOID_PTR":                      "void *",
}

var (
	functionPattern = regexp.MustCompile(`^CK_PKCS11_FUNCTION_INFO\((C_[A-Za-z0-9_]+)\)$`)
	namePattern     = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)$`)
)

func main() {
	check := flag.Bool("check", false, "fail if either generated backend binding is stale instead of rewriting it")
	rootFlag := flag.String("root", "", "repository root; normally discovered automatically")
	flag.Parse()

	root, err := findRepositoryRoot(*rootFlag)
	if err != nil {
		fatal(err)
	}

	input, err := os.ReadFile(filepath.Join(root, sourcePath))
	if err != nil {
		fatal(fmt.Errorf("read %s: %w", sourcePath, err))
	}
	functions, err := parseFunctions(string(input))
	if err != nil {
		fatal(fmt.Errorf("parse %s: %w", sourcePath, err))
	}

	goGenerated, err := renderGo(functions)
	if err != nil {
		fatal(err)
	}
	cGenerated := renderC(functions)
	outputs := []struct {
		path string
		data []byte
	}{
		{path: goOutputPath, data: goGenerated},
		{path: cOutputPath, data: cGenerated},
	}

	for _, output := range outputs {
		path := filepath.Join(root, output.path)
		if *check {
			current, err := os.ReadFile(path)
			if err != nil {
				fatal(fmt.Errorf("read %s: %w", output.path, err))
			}
			if !bytes.Equal(current, output.data) {
				fatal(fmt.Errorf("%s is stale; run `go generate ./...`", output.path))
			}
			continue
		}
		if err := writeIfChanged(path, output.data, 0o644); err != nil {
			fatal(fmt.Errorf("write %s: %w", output.path, err))
		}
	}
}
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gencalls:", err)
	os.Exit(1)
}

func findRepositoryRoot(explicit string) (string, error) {
	if explicit != "" {
		root, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if fileExists(filepath.Join(root, sourcePath)) {
			return root, nil
		}
		return "", fmt.Errorf("%s does not contain %s", root, sourcePath)
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) && fileExists(filepath.Join(dir, sourcePath)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not locate repository root")
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writeIfChanged(path string, data []byte, mode os.FileMode) error {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".function_table_gen-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Windows does not replace an existing destination with os.Rename. Remove
	// the old generated file only after the complete replacement is durable in
	// the temporary file.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(tmpName, path)
}

func parseFunctions(source string) ([]function, error) {
	lines := strings.Split(source, "\n")
	version := versionBase
	functions := make([]function, 0, 104)

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		switch trimmed {
		case "#ifndef CK_PKCS11_2_0_ONLY":
			version = version30
			continue
		case "#ifndef CK_PKCS11_3_0_ONLY":
			version = version32
			continue
		case "#endif /* CK_PKCS11_3_0_ONLY */":
			version = version30
			continue
		case "#endif /* CK_PKCS11_2_0_ONLY */":
			version = versionBase
			continue
		}

		match := functionPattern.FindStringSubmatch(trimmed)
		if match == nil {
			continue
		}

		name := match[1]
		var declaration strings.Builder
		foundOpen := false
		foundClose := false

		for i++; i < len(lines); i++ {
			line := lines[i]
			lineTrimmed := strings.TrimSpace(line)
			if !foundOpen {
				if lineTrimmed == "#ifdef CK_NEED_ARG_LIST" {
					continue
				}
				if strings.Contains(line, "(") {
					foundOpen = true
				}
			}
			if foundOpen {
				declaration.WriteString(line)
				declaration.WriteByte('\n')
				if strings.Contains(line, ");") {
					foundClose = true
					break
				}
			}
		}

		if !foundOpen || !foundClose {
			return nil, fmt.Errorf("%s has no complete argument list", name)
		}

		parameters, err := parseParameters(declaration.String())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		functions = append(functions, function{
			Name:       name,
			Version:    version,
			Parameters: parameters,
		})
	}

	if len(functions) == 0 {
		return nil, errors.New("no CK_PKCS11_FUNCTION_INFO declarations found")
	}
	if err := validateFunctions(functions); err != nil {
		return nil, err
	}
	return functions, nil
}

func parseParameters(block string) ([]parameter, error) {
	withoutComments, err := stripBlockComments(block)
	if err != nil {
		return nil, err
	}

	open := strings.Index(withoutComments, "(")
	close := strings.LastIndex(withoutComments, ");")
	if open < 0 || close < open {
		return nil, errors.New("malformed argument list")
	}
	body := strings.TrimSpace(withoutComments[open+1 : close])
	if body == "" || body == "void" {
		return nil, nil
	}

	parts := strings.Split(body, ",")
	parameters := make([]parameter, 0, len(parts))
	for _, part := range parts {
		declaration := normalizeWhitespace(part)
		if declaration == "" {
			return nil, errors.New("empty parameter declaration")
		}
		match := namePattern.FindStringSubmatch(declaration)
		if match == nil {
			return nil, fmt.Errorf("cannot identify parameter name in %q", declaration)
		}
		name := match[1]
		typePart := strings.TrimSpace(strings.TrimSuffix(declaration, name))
		if typePart == "" {
			return nil, fmt.Errorf("cannot identify parameter type in %q", declaration)
		}
		concreteType, ok := parameterTypes[typePart]
		if !ok {
			return nil, fmt.Errorf("no parameter type mapping for %q", typePart)
		}
		parameters = append(parameters, parameter{
			Declaration: concreteType + " " + name,
			Name:        name,
		})
	}
	return parameters, nil
}

func stripBlockComments(input string) (string, error) {
	var output strings.Builder
	inComment := false
	for i := 0; i < len(input); i++ {
		if inComment {
			if i+1 < len(input) && input[i] == '*' && input[i+1] == '/' {
				inComment = false
				i++
				output.WriteByte(' ')
			}
			continue
		}
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '*' {
			inComment = true
			i++
			output.WriteByte(' ')
			continue
		}
		output.WriteByte(input[i])
	}
	if inComment {
		return "", errors.New("unterminated block comment")
	}
	return output.String(), nil
}

func normalizeWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func validateFunctions(functions []function) error {
	seen := make(map[string]struct{}, len(functions))
	lastVersion := versionBase
	for _, function := range functions {
		if _, ok := seen[function.Name]; ok {
			return fmt.Errorf("duplicate function %s", function.Name)
		}
		seen[function.Name] = struct{}{}
		if function.Version < lastVersion {
			return fmt.Errorf("function-table version regressed at %s", function.Name)
		}
		if len(function.Parameters) > maximumDispatchArguments {
			return fmt.Errorf("%s has %d arguments; native transports support at most %d", function.Name, len(function.Parameters), maximumDispatchArguments)
		}
		lastVersion = function.Version
	}
	return nil
}

func renderGo(functions []function) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString("// Code generated by internal/cmd/gencalls from the pinned OASIS PKCS #11 3.2 pkcs11f.h header; DO NOT EDIT.\n\n")
	output.WriteString("package raw\n\n")
	output.WriteString("type functionID uint16\n\n")
	fmt.Fprintf(&output, "const functionMaximumArguments = %d\n\n", maximumDispatchArguments)
	output.WriteString("const (\n")
	for index, function := range functions {
		name := "function" + strings.TrimPrefix(function.Name, "C_")
		if index == 0 {
			fmt.Fprintf(&output, "\t%s functionID = iota\n", name)
		} else {
			fmt.Fprintf(&output, "\t%s\n", name)
		}
	}
	output.WriteString("\tfunctionCount\n")
	output.WriteString(")\n\n")
	output.WriteString("type functionMetadata struct {\n\tname string\n\tminimum Version\n\targuments uint8\n}\n\n")
	output.WriteString("var functionTableMetadata = [...]functionMetadata{\n")
	for _, function := range functions {
		major, minor := minimumVersion(function.Version)
		fmt.Fprintf(
			&output,
			"\tfunction%s: {name: %q, minimum: Version{Major: %d, Minor: %d}, arguments: %d},\n",
			strings.TrimPrefix(function.Name, "C_"), function.Name, major, minor, len(function.Parameters),
		)
	}
	output.WriteString("}\n")
	formatted, err := format.Source(output.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w", err)
	}
	return formatted, nil
}

func renderC(functions []function) []byte {
	var output bytes.Buffer
	output.WriteString(`/*
 * Code generated by internal/cmd/gencalls from the pinned OASIS PKCS #11
 * 3.2 pkcs11f.h header; DO NOT EDIT.
 *
 * The shared Go implementation identifies a Cryptoki operation by its generated
 * function ID and supplies only native scalar values and pointers. This file is
 * the cgo transport adapter: each switch case selects the correctly versioned
 * function table, casts every uintptr_t to the OASIS-declared C type, and makes
 * the typed indirect call. Missing tables and function pointers return
 * CKR_FUNCTION_NOT_SUPPORTED instead of being dereferenced.
 */
#ifndef P11X_CALLS_GEN_H
#define P11X_CALLS_GEN_H 1

`)
	renderCDispatcher(&output, functions)
	output.WriteString("#endif\n")
	return output.Bytes()
}

func tableAccessor(version tableVersion) (tableType, accessor string) {
	switch version {
	case versionBase:
		return "CK_FUNCTION_LIST_PTR", "p11x_base"
	case version30:
		return "CK_FUNCTION_LIST_3_0_PTR", "p11x_v3"
	case version32:
		return "CK_FUNCTION_LIST_3_2_PTR", "p11x_v32"
	default:
		panic("unknown table version")
	}
}

func renderCDispatcher(output *bytes.Buffer, functions []function) {
	maximumArguments := maximumDispatchArguments

	output.WriteString("/* Generic cgo transport used by the shared Go implementation. */\n")
	fmt.Fprintf(output, "#define P11X_MAX_ARGUMENTS %d\n\n", maximumArguments)
	output.WriteString("static inline CK_RV p11x_dispatch(\n")
	output.WriteString("    p11x_ctx *ctx,\n")
	output.WriteString("    uint16_t function_id,\n")
	output.WriteString("    size_t argument_count")
	for index := range maximumArguments {
		fmt.Fprintf(output, ",\n    uintptr_t a%d", index)
	}
	output.WriteString(") {\n")
	fmt.Fprintf(output, "  const uintptr_t arguments[%d] = {", maximumArguments)
	for index := range maximumArguments {
		if index > 0 {
			output.WriteString(", ")
		}
		fmt.Fprintf(output, "a%d", index)
	}
	output.WriteString("};\n")
	output.WriteString("  switch (function_id) {\n")
	for index, function := range functions {
		tableType, accessor := tableAccessor(function.Version)
		fmt.Fprintf(output, "    case %d: {\n", index)
		fmt.Fprintf(output, "      if (argument_count != %d) return CKR_ARGUMENTS_BAD;\n", len(function.Parameters))
		fmt.Fprintf(output, "      %s f = %s(ctx);\n", tableType, accessor)
		fmt.Fprintf(output, "      if (!f || !f->%s) return CKR_FUNCTION_NOT_SUPPORTED;\n", function.Name)
		fmt.Fprintf(output, "      return f->%s(", function.Name)
		for parameterIndex, parameter := range function.Parameters {
			parameterType := strings.TrimSpace(strings.TrimSuffix(parameter.Declaration, parameter.Name))
			if parameterIndex > 0 {
				output.WriteString(", ")
			}
			fmt.Fprintf(output, "(%s)(uintptr_t)arguments[%d]", parameterType, parameterIndex)
		}
		output.WriteString(");\n")
		output.WriteString("    }\n")
	}
	output.WriteString("    default:\n")
	output.WriteString("      return CKR_FUNCTION_NOT_SUPPORTED;\n")
	output.WriteString("  }\n")
	output.WriteString("}\n\n")
}

func minimumVersion(version tableVersion) (uint8, uint8) {
	switch version {
	case versionBase:
		return 0, 0
	case version30:
		return 3, 0
	case version32:
		return 3, 2
	default:
		panic("unknown table version")
	}
}
