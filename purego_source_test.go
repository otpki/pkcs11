package pkcs11

import (
	"bufio"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNativeBackendsRemainSeparated prevents cgo from leaking into common or
// PureGo production sources. The cgo backend is intentionally retained as the
// default when cgo is enabled, but every file that imports C must be guarded by
// the backend-selection constraint. Conversely, PureGo files must remain usable
// when CGO_ENABLED=0.
func TestNativeBackendsRemainSeparated(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".tool", "reports":
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		buildConstraint := ""
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "//go:build") {
				buildConstraint = line
				break
			}
			if line != "" && !strings.HasPrefix(line, "//") {
				break
			}
		}
		if err := scanner.Err(); err != nil {
			return err
		}

		// C files immediately below raw are translation units compiled by cgo.
		// The implementation sources under raw/internal/cryptoki are included by
		// those wrappers and are not independently considered by the Go package.
		if filepath.Ext(path) == ".c" && filepath.Dir(path) == filepath.Join(root, "raw") {
			if !isCGOTransportConstraint(buildConstraint) {
				t.Errorf("%s is a cgo translation unit without the cgo-backend constraint; got %q", path, buildConstraint)
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ImportsOnly)
		if err != nil {
			return err
		}
		importsC := false
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if name == "C" {
				importsC = true
			}
		}

		if importsC {
			if !isCGOTransportConstraint(buildConstraint) {
				t.Errorf("%s imports C without the cgo-backend constraint; got %q", path, buildConstraint)
			}
		}
		if strings.Contains(filepath.Base(path), "_purego.go") && importsC {
			t.Errorf("%s is a PureGo backend file but imports C", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isCGOTransportConstraint(constraint string) bool {
	return strings.HasPrefix(constraint, "//go:build cgo &&") &&
		strings.Contains(constraint, "!pkcs11_purego")
}
