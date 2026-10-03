// Command genconst generates raw/zconst.go and raw/error_names.go from the
// pinned OASIS PKCS #11 type header. It reads the bundled header rather than a
// host installation so generation is deterministic on every machine.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"go/parser"
	"os"
	"slices"
	"strings"
	"unicode"
)

const (
	defaultInput            = "raw/internal/cryptoki/oasis/3.2/pkcs11t.h"
	defaultConstantsOutput  = "raw/zconst.go"
	defaultErrorNamesOutput = "raw/error_names.go"
)

var excludedMacros = map[string]struct{}{
	// These names control how the C headers are expanded. They are not
	// Cryptoki values and therefore must not become part of the Go API.
	"CK_NEED_ARG_LIST":   {},
	"CK_PKCS11_2_0_ONLY": {},
	"CK_PKCS11_3_0_ONLY": {},
}

type options struct {
	input            string
	constantsOutput  string
	errorNamesOutput string
	check            bool
}

func main() {
	var opts options
	flag.StringVar(&opts.input, "input", defaultInput, "path to the pinned OASIS pkcs11t.h")
	flag.StringVar(&opts.constantsOutput, "constants-output", defaultConstantsOutput, "path to the generated constants Go source")
	flag.StringVar(&opts.errorNamesOutput, "error-names-output", defaultErrorNamesOutput, "path to the generated CKR name table Go source")
	flag.BoolVar(&opts.check, "check", false, "verify that both outputs are current without rewriting them")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "genconst:", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	header, err := os.ReadFile(opts.input)
	if err != nil {
		return fmt.Errorf("read %s: %w", opts.input, err)
	}

	constants, err := parseConstants(header)
	if err != nil {
		return fmt.Errorf("parse %s: %w", opts.input, err)
	}

	generatedConstants, err := renderConstants(constants, opts.input)
	if err != nil {
		return err
	}
	generatedErrorNames, err := renderErrorNames(constants, opts.input)
	if err != nil {
		return err
	}

	outputs := []struct {
		path string
		data []byte
	}{
		{path: opts.constantsOutput, data: generatedConstants},
		{path: opts.errorNamesOutput, data: generatedErrorNames},
	}
	for _, output := range outputs {
		formatted, err := formatGeneratedGo(output.path, output.data)
		if err != nil {
			return err
		}
		if err := syncGeneratedFile(output.path, formatted, opts.check); err != nil {
			return err
		}
	}
	return nil
}

// formatGeneratedGo applies the same formatter used by gofmt before generated
// source is compared or written. Keeping formatting at the output boundary
// ensures every Go file produced by this command follows one policy, including
// any future output added alongside zconst.go and error_names.go.
func formatGeneratedGo(path string, source []byte) ([]byte, error) {
	formatted, err := format.Source(source)
	if err != nil {
		return nil, fmt.Errorf("format %s: %w", path, err)
	}
	return formatted, nil
}

func syncGeneratedFile(path string, generated []byte, check bool) error {
	current, err := os.ReadFile(path)
	if check {
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("%s is stale; run `go generate ./...`", path)
		}
		return nil
	}

	if err == nil && bytes.Equal(current, generated) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.WriteFile(path, generated, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// parseConstants extracts object-like CK* macros from pkcs11t.h. Function-like
// macros are ignored. The parser is deliberately small because the pinned
// header's public constants use only integer literals, aliases, parentheses,
// and ordinary integer operators.
func parseConstants(source []byte) (map[string]string, error) {
	cleaned, err := stripCComments(string(source))
	if err != nil {
		return nil, err
	}
	cleaned = strings.ReplaceAll(cleaned, "\\\r\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\\\n", "")

	constants := make(map[string]string)
	lineNumber := 0
	for line := range strings.SplitSeq(cleaned, "\n") {
		lineNumber++
		name, expression, ok := parseDefine(line)
		if !ok || !strings.HasPrefix(name, "CK") {
			continue
		}
		if _, excluded := excludedMacros[name]; excluded {
			continue
		}

		normalized, err := normalizeExpression(expression)
		if err != nil {
			return nil, fmt.Errorf("line %d, %s: %w", lineNumber, name, err)
		}
		if previous, exists := constants[name]; exists && previous != normalized {
			return nil, fmt.Errorf("line %d: conflicting definitions for %s: %q and %q", lineNumber, name, previous, normalized)
		}
		constants[name] = normalized
	}

	if len(constants) == 0 {
		return nil, errors.New("no PKCS #11 constants found")
	}
	if _, ok := constants["CK_UNAVAILABLE_INFORMATION"]; !ok {
		return nil, errors.New("CK_UNAVAILABLE_INFORMATION was not found")
	}
	return constants, nil
}

// parseDefine returns an object-like preprocessor definition. A function-like
// macro is identified by an opening parenthesis immediately after its name;
// whitespace followed by a parenthesized expression is still object-like.
func parseDefine(line string) (name, expression string, ok bool) {
	trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
	if !strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	trimmed = strings.TrimLeftFunc(trimmed[1:], unicode.IsSpace)
	if !strings.HasPrefix(trimmed, "define") {
		return "", "", false
	}
	if len(trimmed) > len("define") && !unicode.IsSpace(rune(trimmed[len("define")])) {
		return "", "", false
	}
	trimmed = strings.TrimLeftFunc(trimmed[len("define"):], unicode.IsSpace)
	if trimmed == "" || !isIdentStart(rune(trimmed[0])) {
		return "", "", false
	}

	end := 1
	for end < len(trimmed) && isIdentContinue(rune(trimmed[end])) {
		end++
	}
	name = trimmed[:end]
	tail := trimmed[end:]
	if strings.HasPrefix(tail, "(") {
		return "", "", false
	}
	expression = strings.TrimSpace(tail)
	if expression == "" {
		return "", "", false
	}
	return name, expression, true
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentContinue(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

// normalizeExpression converts the small C integer-expression dialect used by
// the OASIS constants into valid Go. In particular, it removes C integer
// suffixes and translates C's bitwise-complement operator from ~ to ^.
func normalizeExpression(expression string) (string, error) {
	expression = stripOuterParentheses(strings.TrimSpace(expression))
	var output strings.Builder

	for index := 0; index < len(expression); {
		character := expression[index]
		switch {
		case unicode.IsSpace(rune(character)):
			index++
		case isIdentStart(rune(character)):
			end := index + 1
			for end < len(expression) && isIdentContinue(rune(expression[end])) {
				end++
			}
			writeToken(&output, expression[index:end])
			index = end
		case character >= '0' && character <= '9':
			end := index + 1
			if character == '0' && end < len(expression) && (expression[end] == 'x' || expression[end] == 'X') {
				end++
				for end < len(expression) && isHexDigit(expression[end]) {
					end++
				}
			} else {
				for end < len(expression) && expression[end] >= '0' && expression[end] <= '9' {
					end++
				}
			}
			literalEnd := end
			for end < len(expression) && strings.ContainsRune("uUlL", rune(expression[end])) {
				end++
			}
			writeToken(&output, expression[index:literalEnd])
			index = end
		case strings.ContainsRune("()|&^~+-*/%", rune(character)):
			tokenText := string(character)
			if character == '~' {
				tokenText = "^"
			}
			if (character == '<' || character == '>') && index+1 < len(expression) && expression[index+1] == character {
				tokenText = expression[index : index+2]
				index++
			}
			writeToken(&output, tokenText)
			index++
		case (character == '<' || character == '>') && index+1 < len(expression) && expression[index+1] == character:
			writeToken(&output, expression[index:index+2])
			index += 2
		default:
			return "", fmt.Errorf("unsupported character %q in expression %q", character, expression)
		}
	}

	normalized := strings.TrimSpace(output.String())
	if normalized == "^ 0" || normalized == "^0" {
		normalized = "^uint(0)"
	}
	if _, err := parser.ParseExpr(normalized); err != nil {
		return "", fmt.Errorf("translate %q as %q: %w", expression, normalized, err)
	}
	return normalized, nil
}

func writeToken(output *strings.Builder, tokenText string) {
	if output.Len() > 0 {
		output.WriteByte(' ')
	}
	output.WriteString(tokenText)
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func stripOuterParentheses(value string) string {
	for len(value) >= 2 && value[0] == '(' && value[len(value)-1] == ')' && outerParenthesesEncloseAll(value) {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	return value
}

func outerParenthesesEncloseAll(value string) bool {
	depth := 0
	for index, character := range value {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && index != len(value)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func renderConstants(constants map[string]string, input string) ([]byte, error) {
	unavailable := constants["CK_UNAVAILABLE_INFORMATION"]
	if unavailable != "^uint(0)" {
		return nil, fmt.Errorf("CK_UNAVAILABLE_INFORMATION normalized to %q, want ^uint(0)", unavailable)
	}

	names := make([]string, 0, len(constants)-1)
	for name := range constants {
		if name != "CK_UNAVAILABLE_INFORMATION" {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	var output bytes.Buffer
	fmt.Fprintln(&output, "// Code generated by internal/cmd/genconst from the bundled OASIS PKCS #11 3.2 headers; DO NOT EDIT.")
	fmt.Fprintf(&output, "// Source: %s\n", input)
	fmt.Fprintln(&output, "package raw")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "const (")
	for _, name := range names {
		fmt.Fprintf(&output, "\t%s uint = %s\n", name, constants[name])
	}
	fmt.Fprintln(&output, ")")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "// CK_UNAVAILABLE_INFORMATION is all one bits at the native CK_ULONG width.")
	fmt.Fprintln(&output, "// The platform-specific backing constant preserves Cryptoki's LLP64 value on")
	fmt.Fprintln(&output, "// Windows while keeping this name usable in Go constant expressions.")
	fmt.Fprintln(&output, "const CK_UNAVAILABLE_INFORMATION = ckUnavailableInformation")

	return output.Bytes(), nil
}

// renderErrorNames creates the symbolic lookup table used by Error.Error.
// Every CKR_* constant comes from the same parsed header data as zconst.go, so
// the numeric constants and their printable names cannot drift independently.
func renderErrorNames(constants map[string]string, input string) ([]byte, error) {
	names := make([]string, 0)
	for name := range constants {
		if strings.HasPrefix(name, "CKR_") {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no PKCS #11 return-value constants found")
	}
	if _, ok := constants["CKR_OK"]; !ok {
		return nil, errors.New("CKR_OK was not found")
	}
	slices.Sort(names)

	var output bytes.Buffer
	fmt.Fprintln(&output, "// Code generated by internal/cmd/genconst from the bundled OASIS PKCS #11 3.2 headers; DO NOT EDIT.")
	fmt.Fprintf(&output, "// Source: %s\n", input)
	fmt.Fprintln(&output, "package raw")
	fmt.Fprintln(&output)
	fmt.Fprintln(&output, "var errorNames = map[uint]string{")
	for _, name := range names {
		fmt.Fprintf(&output, "\t%s: %q,\n", name, name)
	}
	fmt.Fprintln(&output, "}")

	return output.Bytes(), nil
}

// stripCComments removes C block and line comments while retaining newlines so
// parse errors can still report useful source line numbers.
func stripCComments(source string) (string, error) {
	var output strings.Builder
	inBlock := false
	inLine := false
	inString := false
	inCharacter := false
	escaped := false

	for index := 0; index < len(source); index++ {
		current := source[index]
		next := byte(0)
		if index+1 < len(source) {
			next = source[index+1]
		}

		if inBlock {
			if current == '*' && next == '/' {
				inBlock = false
				index++
				continue
			}
			if current == '\n' {
				output.WriteByte('\n')
			}
			continue
		}
		if inLine {
			if current == '\n' {
				inLine = false
				output.WriteByte('\n')
			}
			continue
		}
		if inString || inCharacter {
			output.WriteByte(current)
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if inString && current == '"' {
				inString = false
			}
			if inCharacter && current == '\'' {
				inCharacter = false
			}
			continue
		}

		switch {
		case current == '/' && next == '*':
			inBlock = true
			index++
		case current == '/' && next == '/':
			inLine = true
			index++
		case current == '"':
			inString = true
			output.WriteByte(current)
		case current == '\'':
			inCharacter = true
			output.WriteByte(current)
		default:
			output.WriteByte(current)
		}
	}
	if inBlock {
		return "", errors.New("unterminated block comment")
	}
	return output.String(), nil
}
