// Package proxycmd builds the pkcs11-proxy command tree.
package proxycmd

import (
	"cmp"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/vendors/all"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const commandDescription = `Run a PKCS #11 proxy broker.

The proxy opens one or more local PKCS #11 modules and makes their tokens
available to remote clients. Each target has a route name. Clients can call
proxy.ListRoutes to find the available routes before connecting.

The first client login activates a token with its PIN. Later clients must use
the same PIN. The server does not store a plaintext PIN. By default, any
authenticated client can use every operation.

Settings use the same names in flags, PKCS11_PROXY_* environment variables,
and YAML. Precedence is flag, environment, YAML, then default. targets[] and
discovery are YAML-only. Discovery can publish one route per reported token.

Use --test for an in-memory HSM with PIN "1234". This is useful for trying the
proxy and dashboard without a real HSM.

logging.* controls logs, audit.* controls the signed audit log, and otel.*
controls OpenTelemetry export. health.listen serves /healthz, /readyz, and
/metrics for local monitoring.

Use the pki subcommand to create development mTLS certificates. Use audit to
verify or inspect audit logs.`

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

// Options configures one command tree without process-global registration.
type Options struct {
	Version string
	// Vendors is the complete bundled set. Nil selects public vendors.
	// A non-nil empty slice deliberately selects standards-only behavior.
	// VendorModule implementations must be immutable and concurrency-safe.
	Vendors []pkcs11.VendorModule
}

// newServeCommand builds the serve command and loads its configuration.
func newServeCommand(version string, vendors []pkcs11.VendorModule) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "serve",
		Version: version,
		Short:   "Run the proxy broker",
		Long: `Run the proxy broker.

Most settings use the same dotted name in flags and YAML, with a matching
PKCS11_PROXY_* environment variable. Precedence is flag, environment, YAML,
then default. targets[] and discovery are YAML-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadOptions(cmd.Flags())
			if err != nil {
				return err
			}
			cfg.bundledVendors = vendors
			if cfg.Test {
				if len(cfg.Targets) > 0 {
					slog.Warn("--test ignores configured targets", "targets", len(cfg.Targets))
				}
				if len(cfg.Discovery) > 0 {
					slog.Warn("--test ignores configured discovery", "modules", len(cfg.Discovery))
					cfg.Discovery = nil
				}
				cfg.Targets = testTargets()
			}
			return run(cmd.Context(), cfg)
		},
	}
	registerServeFlags(cmd.Flags())
	return cmd
}

// New builds an independent command tree. The caller owns execution and signals.
func New(opts Options) *cobra.Command {
	version := opts.Version
	version = cmp.Or(version, "dev")
	modules := opts.Vendors
	if modules == nil {
		modules = all.Modules()
	}
	// make preserves the distinction between nil and explicitly empty.
	vendors := make([]pkcs11.VendorModule, len(modules))
	copy(vendors, modules)
	// A bare root command prints help instead of starting the broker.
	root := &cobra.Command{
		Use:     "pkcs11-proxy",
		Version: version,
		Short:   "PKCS #11 proxy broker",
		Long:    commandDescription,
		Example: commandExamples,
	}
	// Hide completion commands from generated reference docs.
	root.CompletionOptions.HiddenDefaultCmd = true
	root.AddCommand(
		newServeCommand(version, vendors),
		newAuditCommand(),
		newPKICommand(),
		newVendorsCommand(vendors),
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

	disableAutoGenTags(root)
	return root
}

func disableAutoGenTags(cmd *cobra.Command) {
	cmd.DisableAutoGenTag = true
	for _, child := range cmd.Commands() {
		disableAutoGenTags(child)
	}
}

func newVendorsCommand(vendors []pkcs11.VendorModule) *cobra.Command {
	return &cobra.Command{
		Use:   "vendors",
		Short: "List the vendor modules compiled into this binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, module := range vendors {
				definition := module.Definition()
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", definition.ID, definition.Name); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func run(ctx context.Context, cfg options) error {
	// Observability order: logging first so every later step is observable,
	// then the audit sink and OTLP providers. Deferred closes run in reverse:
	// the async logger drains last so shutdown messages are flushed.
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
	// Deferred Close covers failures before the graceful shutdown sequence
	// begins; that sequence owns teardown itself once draining starts. Both
	// paths are bounded by shutdown_timeout so a wedged native call cannot
	// hold process exit hostage.
	earlyClose := true
	defer func() { //nolint:contextcheck // Close must proceed after the serving ctx is canceled.
		if earlyClose {
			if err := teardownWithDeadline(cfg.ShutdownTimeout, server.Close); err != nil {
				slog.Warn("server close incomplete", "error", err)
			}
		}
	}()
	serverID := server.InstanceID()
	slog.Info("listening",
		"routes", server.TargetIDs(), "listen", cfg.Listen,
		"insecure", cfg.Insecure, "server_id", hex.EncodeToString(serverID[:]))
	for _, route := range server.RouteCatalog() {
		if strings.HasPrefix(route.TokenSerial, "TEST-") {
			slog.Info("route bound to in-memory test module", "route", route.ID, "user_pin", testmock.DefaultPIN)
		}
	}
	// The health listener binds before Serve so a refused address fails
	// startup rather than surfacing later. Its shutdown is deferred past the
	// drain sequence: /readyz answers 503 and /healthz 200 while the broker
	// drains, giving the orchestrator the whole drain timeout to stop routing.
	healthAddr := ""
	if cfg.Health.Listen != "" {
		endpoints := &healthServer{source: server, metrics: providers.metricsHandler()}
		listener, err := startHealthListener(cfg.Health.Listen, cfg.Health.AllowRemote, endpoints.Handler())
		if err != nil {
			return err
		}
		defer func() { //nolint:contextcheck // Shutdown must outlive the canceled serving ctx.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := listener.Shutdown(shutdownCtx); err != nil {
				slog.Warn("health listener shutdown failed", "error", err)
			}
		}()
		healthAddr = listener.Addr()
		slog.Info("health listener serving",
			"url", fmt.Sprintf("http://%s", healthAddr), "endpoints", "/healthz /readyz /metrics")
	}
	if cfg.DevUI.Enabled {
		dashboard := newDevUI(server, cfg.Listen)
		dashboard.logHandler = logHandler
		dashboard.audit = audit
		dashboard.otel = cfg.OTel.Endpoint != ""
		dashboard.healthListen = healthAddr
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
	earlyClose = false
	server.Drain(ctx)
	slog.Info("draining",
		"timeout", cfg.DrainTimeout, "logical_clients", server.LogicalClients())
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	waitErr := server.WaitDrained(drainCtx) //nolint:contextcheck // Drain intentionally outlives the canceled serving ctx.
	cancelDrain()
	if waitErr != nil {
		slog.Warn("drain expired; forcing shutdown", "logical_clients", server.LogicalClients())
	}
	// Shutdown waits for in-flight requests and closes physical HSM sessions.
	// A native call that never returns cannot be preempted, so teardown is
	// bounded: past shutdown_timeout the process exits with those requests
	// still in flight rather than hanging scale-down forever.
	if err := teardownWithDeadline(cfg.ShutdownTimeout, server.Shutdown); err != nil { //nolint:contextcheck // Shutdown intentionally detaches from the canceled serving ctx.
		slog.Warn("forced shutdown incomplete", "error", err)
	}
	if err := <-serveDone; err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// teardownWithDeadline runs teardown on a detached context with a hard
// wall-clock bound. Shutdown and Close wait for request handlers whose native
// HSM calls may be wedged beyond any context cancellation; past the deadline
// the caller proceeds and the abandoned goroutine dies with the process.
func teardownWithDeadline(timeout time.Duration, teardown func(context.Context) error) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	done := make(chan error, 1)
	// Teardown detaches from the canceled serving ctx intentionally.
	go func() { done <- teardown(context.Background()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("teardown did not finish within %s; abandoning in-flight requests", timeout)
	}
}
