package main

import (
	"context"
	"os"
	"path/filepath"
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
