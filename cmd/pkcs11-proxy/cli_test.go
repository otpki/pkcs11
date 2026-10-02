package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagCmd returns a parsed serve flagset for binding tests.
func flagCmd(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	cmd := &cobra.Command{}
	registerServeFlags(cmd.Flags())
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return cmd.Flags()
}

// TestViperFlagEnvConfigPrecedence exercises the resolution chain the serve
// command depends on: flag > env > config file > default.
func TestViperFlagEnvConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(configPath, []byte("listen: \"10.0.0.9:1111\"\ninsecure: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default.
	cfg, err := loadOptions(flagCmd(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9443" || cfg.Insecure || cfg.Test {
		t.Fatalf("defaults = %+v", cfg)
	}

	// Config file beats defaults.
	cfg, err = loadOptions(flagCmd(t, "--config", configPath))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "10.0.0.9:1111" || !cfg.Insecure {
		t.Fatalf("config = %+v", cfg)
	}

	// Env beats the config file.
	t.Setenv("PKCS11_PROXY_LISTEN", "10.0.0.7:2222")
	cfg, err = loadOptions(flagCmd(t, "--config", configPath))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "10.0.0.7:2222" {
		t.Fatalf("env precedence = %q", cfg.Listen)
	}

	// Flag beats env.
	cfg, err = loadOptions(flagCmd(t, "--config", configPath, "--listen", "10.0.0.8:3333"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "10.0.0.8:3333" {
		t.Fatalf("flag precedence = %q", cfg.Listen)
	}
}

// TestViperNestedFlags covers flags named exactly like their nested config
// keys — every scalar option resolves through the same identifier.
func TestViperNestedFlags(t *testing.T) {
	cfg, err := loadOptions(flagCmd(t,
		"--dev_ui.enabled", "--test",
		"--otel.endpoint", "collector:4318",
		"--sessions.max_queued", "12",
		"--audit.path", "/tmp/a.log",
	))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DevUI.Enabled || !cfg.Test {
		t.Fatalf("dev_ui.enabled/test = %v/%v", cfg.DevUI.Enabled, cfg.Test)
	}
	if cfg.OTel.Endpoint != "collector:4318" || cfg.Sessions.MaxQueued != 12 || cfg.Audit.Path != "/tmp/a.log" {
		t.Fatalf("nested flags = %+v", cfg)
	}
}

// writeConfig writes yaml into a fresh config file and returns its path.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireLoadError fails the test when loading options with args succeeds.
// It also fails it when the error lacks one of wants.
func requireLoadError(t *testing.T, args []string, wants ...string) {
	t.Helper()
	_, err := loadOptions(flagCmd(t, args...))
	if err == nil {
		t.Fatalf("loadOptions(%q) returned no error", args)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %s", err, want)
		}
	}
}

// TestConfigFileUnknownKeyFailsLoad pins the full dotted path the error names.
func TestConfigFileUnknownKeyFailsLoad(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, key string
	}{
		{"top level", "listen_address: \"10.0.0.9:1111\"\n", "listen_address"},
		{"section", "sessions:\n  max_quued: 3\n", "sessions.max_quued"},
		{"targets entry", "targets:\n  - name: hsm\n    modul: /opt/hsm.so\n", "targets[0].modul"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.yaml)
			requireLoadError(t, []string{"--config", path}, fmt.Sprintf("config file %q: unknown key %q", path, tc.key))
		})
	}
}

// TestDefaultConfigFileUnknownKeyFailsLoad puts the unknown key in
// ./pkcs11-proxy.yaml. loadOptions reads that file when --config is empty.
func TestDefaultConfigFileUnknownKeyFailsLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configBaseName+".yaml"), []byte("listen_address: \"10.0.0.9:1111\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	requireLoadError(t, nil, `config file "./pkcs11-proxy.yaml": unknown key "listen_address"`)
}

// TestConfigFileNamesFirstUnknownKey pins the sorted order. A file with
// several unknown keys then fails with one message on every run.
func TestConfigFileNamesFirstUnknownKey(t *testing.T) {
	path := writeConfig(t, "zz_unknown: 1\naa_unknown: 2\n")
	_, err := loadOptions(flagCmd(t, "--config", path))
	if err == nil || !strings.Contains(err.Error(), `unknown key "aa_unknown"`) || strings.Contains(err.Error(), "zz_unknown") {
		t.Fatalf("error = %v, want it to name aa_unknown alone", err)
	}
}

// TestConfigFileUndecodableValueFailsUnderFlag overrides an undecodable file
// value with a flag. The file decodes on its own and still fails.
func TestConfigFileUndecodableValueFailsUnderFlag(t *testing.T) {
	path := writeConfig(t, "sessions:\n  max_queued: \"many\"\n")
	requireLoadError(t, []string{"--config", path, "--sessions.max_queued", "12"},
		fmt.Sprintf("config file %q", path), "sessions.max_queued")
}

// TestExampleConfigLoads guards the shipped example against unknown keys.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := loadOptions(flagCmd(t, "--config", configBaseName+".example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Module != "/opt/vendor/lib/libpkcs11.so" {
		t.Fatalf("targets = %+v", cfg.Targets)
	}
}

// TestUnknownEnvironmentVariableIsIgnored keeps PKCS11_PROXY_* resolution
// unchanged. The key check reads the config file alone.
func TestUnknownEnvironmentVariableIsIgnored(t *testing.T) {
	t.Setenv("PKCS11_PROXY_NO_SUCH_KEY", "1")
	cfg, err := loadOptions(flagCmd(t, "--config", writeConfig(t, "insecure: true\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Insecure {
		t.Fatalf("config = %+v", cfg)
	}
}

// TestPKICommandFlow drives the real command tree: init writes a tree, issue
// adds a client under the reloaded CA, and overwriting refuses without force.
func TestPKICommandFlow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")

	init := newPKICommand()
	init.SetArgs([]string{"init", "--dir", dir, "--host", "127.0.0.1", "--client", "alice"})
	if err := init.Execute(); err != nil {
		t.Fatalf("pki init: %v", err)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "clients/alice.pem", "clients/alice.key"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("init did not write %s: %v", name, err)
		}
	}

	issue := newPKICommand()
	issue.SetArgs([]string{"issue", "client", "--dir", dir, "--name", "bob"})
	if err := issue.Execute(); err != nil {
		t.Fatalf("pki issue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "clients", "bob.pem")); err != nil {
		t.Fatalf("issue did not write client cert: %v", err)
	}

	// Re-init refuses to clobber without --force.
	reinit := newPKICommand()
	reinit.SetArgs([]string{"init", "--dir", dir})
	if err := reinit.Execute(); err == nil {
		t.Fatal("re-init without --force succeeded over existing files")
	}
}

// auditTestWriter writes a small sealed audit log for the CLI tests.
func auditTestWriter(t *testing.T) (logPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.log")
	keyPath = filepath.Join(dir, "audit.key")
	writer, err := auditlog.Open(logPath, keyPath, auditlog.Options{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		writer.AuditProxy(context.Background(), proxy.AuditEvent{Type: "login_grant", Target: "hsm"})
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return logPath, keyPath
}

// TestAuditCommandFlow exercises verify/inspect/prove against a real log.
func TestAuditCommandFlow(t *testing.T) {
	logPath, keyPath := auditTestWriter(t)
	pubPath := keyPath + ".pub"

	for _, args := range [][]string{
		{"verify", logPath, "--key", pubPath},
		{"inspect", logPath, "--tail", "5"},
		{"prove", logPath, "--seq", "1", "--key", pubPath},
	} {
		cmd := newAuditCommand()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("audit %v: %v", args[0], err)
		}
	}

	// Proving without --seq fails fast.
	cmd := newAuditCommand()
	cmd.SetArgs([]string{"prove", logPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("prove without --seq succeeded")
	}
}
