//go:generate go run . docs ../../docs/cli

// Command pkcs11-proxy runs a PKCS #11 proxy broker over one or more local
// token modules. Clients activate the HSM by supplying the PIN with their
// login; the broker never stores or persists it, and every client must
// re-present the activating PIN before it may use the token, so one workload
// cannot piggyback on another's activation.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const commandDescription = `Run a PKCS #11 proxy broker.

The broker owns one or more local PKCS #11 modules and multiplexes remote
clients onto them. Each configured target publishes one token as its own
route; clients pick a route by name and can discover the catalog through
proxy.ListRoutes. There is no server-side PIN: the first client to log in
activates the token with the PIN it supplies, and every other client must
present that same PIN before it is granted access. Authorization is open —
any authenticated client may use every operation.

Every option resolves flag > PKCS11_PROXY_* env > YAML (--config or
./pkcs11-proxy.yaml) > default, with the same name on all three surfaces:
--tls.cert_file, PKCS11_PROXY_TLS_CERT_FILE, and tls.cert_file are one option.
targets[] is the only YAML-only option.

--test replaces configured targets with synthetic routes on the in-memory test
module (user PIN "1234"), for exercising the dashboard and proxy client without
an HSM. A config may also bind individual routes to it with module: "test".

Observability: logging.* drives a non-blocking slog pipeline, audit.* an
Ed25519-signed Merkle-sealed audit log (see the audit subcommands), and
otel.* OTLP/HTTP export of the §30 metrics plus request traces and logs.

Subcommands: "pki" mints a development mTLS tree (CA, server, and client
certificates) for tls.* configuration, and "audit" verifies, inspects, and
extracts inclusion proofs from signed audit logs.`

const commandExamples = `  # Run with the example configuration
  pkcs11-proxy serve --config ./pkcs11-proxy.yaml

  # Serve the read-only dev dashboard alongside the broker
  pkcs11-proxy serve --config ./pkcs11-proxy.yaml --dev_ui.enabled

  # Dev mode: three synthetic routes on in-memory test modules (PIN "1234")
  pkcs11-proxy serve --test --insecure --dev_ui.enabled

  # Mint a development mTLS tree: CA + server + client certs under ./pki
  pkcs11-proxy pki init --dir ./pki --host 10.0.0.5 --client alice

  # Offline-verify a signed audit log, inspect records, prove one entry
  pkcs11-proxy audit verify audit.log --key audit.log.key.pub
  pkcs11-proxy audit inspect audit.log --tail 10
  pkcs11-proxy audit prove audit.log --seq 7 --key audit.log.key.pub`

// version is stamped at release time via
// -ldflags "-X main.version=v1.2.3"; dev builds report "dev".
var version = "dev"

// newServeCommand builds the broker command: the config-key flags plus the
// RunE that loads options through viper and starts the broker.
func newServeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "serve",
		Version: version,
		Short:   "Run the proxy broker",
		Long: `Run the proxy broker.

Every flag below is one option on three surfaces: the flag itself, the same
dotted key in the YAML config (--config or ./pkcs11-proxy.yaml), and a
PKCS11_PROXY_* environment variable — --otel.endpoint, otel.endpoint, and
PKCS11_PROXY_OTEL_ENDPOINT are one setting. Precedence: flag > env > config >
default. targets[] is the only YAML-only option. An unknown key in the config
file fails startup naming it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadOptions(cmd.Flags())
			if err != nil {
				return err
			}
			if cfg.Test {
				if len(cfg.Targets) > 0 {
					slog.Warn("--test ignores configured targets", "targets", len(cfg.Targets))
				}
				cfg.Targets = testTargets()
			}
			return run(cmd.Context(), cfg)
		},
	}
	registerServeFlags(cmd.Flags())
	return cmd
}

func main() {
	// The root is a command group only — no flags, no RunE — so a bare
	// invocation prints help instead of starting anything.
	root := &cobra.Command{
		Use:     "pkcs11-proxy",
		Version: version,
		Short:   "PKCS #11 proxy broker",
		Long:    commandDescription,
		Example: commandExamples,
	}
	// Hidden from help and doc generation — the shell-completion boilerplate
	// is noise in a config reference.
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddCommand(
		newServeCommand(),
		newAuditCommand(),
		newPKICommand(),
		&cobra.Command{
			Use:    "docs <dir>",
			Short:  "Generate markdown command documentation",
			Hidden: true,
			Args:   cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if err := os.MkdirAll(args[0], 0o750); err != nil {
					return err
				}
				return doc.GenMarkdownTree(root, args[0])
			},
		},
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := root.ExecuteContext(ctx)
	stop()
	if err != nil {
		slog.Error("pkcs11-proxy failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg options) error {
	// Observability order: logging first so every later step is observable,
	// then the audit sink and OTLP providers. Deferred closes run in reverse:
	// the async logger drains last so shutdown messages are flushed.
	//nolint:contextcheck // The async log pump must outlive setup ctx; it drains on Close.
	logHandler, err := setupLogging(cfg)
	if err != nil {
		return err
	}
	defer logHandler.Close()
	audit, err := setupAudit(cfg)
	if err != nil {
		return err
	}
	if audit != nil {
		defer func() {
			if err := audit.Close(); err != nil {
				slog.Error("audit log close failed", "error", err)
			}
		}()
	}
	providers, err := setupOTel(ctx, cfg)
	if err != nil {
		return err
	}
	//nolint:contextcheck // Shutdown must proceed after the serve context is canceled.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := providers.Shutdown(shutdownCtx); err != nil {
			slog.Error("otel shutdown failed", "error", err)
		}
	}()

	server, err := newServerOn(ctx, cfg, nil, auditSink(audit))
	if err != nil {
		return err
	}
	defer func() { _ = server.Close(ctx) }()
	serverID := server.InstanceID()
	slog.Info("listening",
		"routes", server.TargetIDs(), "listen", cfg.Listen,
		"insecure", cfg.Insecure, "server_id", hex.EncodeToString(serverID[:]))
	for _, route := range server.RouteCatalog() {
		if strings.HasPrefix(route.TokenSerial, "TEST-") {
			slog.Info("route bound to in-memory test module", "route", route.ID, "user_pin", testmock.DefaultPIN)
		}
	}
	if cfg.DevUI.Enabled {
		dashboard := newDevUI(server, cfg.Listen)
		dashboard.logHandler = logHandler
		dashboard.audit = audit
		dashboard.otel = providers != nil
		dashboard.tlsMode = "insecure"
		if cfg.TLS.CertFile != "" {
			dashboard.tlsMode = "tls"
			if cfg.TLS.ClientCAFile != "" {
				dashboard.tlsMode = "mtls"
			}
		}
		address, err := startDevUI(ctx, cfg.DevUI.Listen, cfg.DevUI.AllowRemote, dashboard)
		if err != nil {
			return err
		}
		slog.Info("dev dashboard", "url", fmt.Sprintf("http://%s/dev/", address))
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	// Shutdown signal: ctx cancel flips the server to draining (the listener
	// stays open for pinned clients), existing logical clients are given the
	// drain timeout to finish, then the process tears down. A Serve failure
	// before shutdown returns immediately.
	select {
	case err := <-serveDone:
		return err
	case <-ctx.Done():
	}
	server.Drain(ctx)
	slog.Info("draining",
		"timeout", cfg.DrainTimeout, "logical_clients", server.LogicalClients())
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	waitErr := server.WaitDrained(drainCtx) //nolint:contextcheck // Drain intentionally outlives the canceled serving ctx.
	cancelDrain()
	if waitErr != nil {
		slog.Warn("drain expired; forcing shutdown", "logical_clients", server.LogicalClients())
	}
	_ = server.Shutdown(context.Background()) //nolint:contextcheck // Shutdown intentionally uses a detached ctx after serving ended.
	if err := <-serveDone; err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
