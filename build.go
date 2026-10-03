//go:build ignore

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run build.go")
		os.Exit(1)
	}
	root, err := os.Getwd()
	if err == nil {
		err = build(root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
}

func build(root string) error {
	dir := root
	vendors := filepath.Join(root, "pkcs11-private-vendors")
	info, err := os.Stat(filepath.Join(vendors, "go.mod"))
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return errors.New("pkcs11-private-vendors/go.mod is not a regular file")
		}
		dir = vendors
		fmt.Println("Building with private vendors")
	case errors.Is(err, os.ErrNotExist):
		fmt.Println("Building with public vendors")
	default:
		return err
	}

	targetOS := os.Getenv("GOOS")
	if targetOS == "" {
		targetOS = runtime.GOOS
	}
	name := "pkcs11-proxy"
	if targetOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(root, "dist", name)
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	version := resolveVersion(root)
	fmt.Println("Version:", version)
	// The private go.mod has an ordinary local replace pointing at the parent.
	// Let Go resolve/update module metadata normally, never edit it ourselves.
	cmd := exec.Command("go", "build", "-mod=mod", "-trimpath",
		"-ldflags", "-s -w -X main.version="+version,
		"-o", output, "./cmd/pkcs11-proxy")
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// resolveVersion builds the development version string from GIT_TAG or the tag at HEAD, then
// GIT_BRANCH or the current branch, and finally "dev". A known commit adds its short hash.
func resolveVersion(dir string) string {
	version := envOr("GIT_TAG", git(dir, "tag", "--points-at", "HEAD"))
	if version == "" {
		version = envOr("GIT_BRANCH", git(dir, "symbolic-ref", "--short", "HEAD"))
	}
	hash := envOr("GIT_HASH", git(dir, "rev-parse", "--short", "HEAD"))
	if version == "" {
		version = "dev"
	}
	if hash != "" {
		version += "-" + hash
	}
	if git(dir, "status", "--porcelain") != "" {
		version += "-dirty"
	}
	return version
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func git(dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line)
}
