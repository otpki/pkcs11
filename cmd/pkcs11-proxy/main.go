// Command pkcs11-proxy runs a PKCS #11 proxy broker over one or more local
// token modules. Clients activate the HSM by supplying the PIN with their
// login; the broker never stores or persists it, and every client must
// re-present the activating PIN before it may use the token, so one workload
// cannot piggyback on another's activation.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

const commandDescription = `Run a PKCS #11 proxy broker.

The broker owns the local PKCS #11 module and multiplexes remote clients onto
it. There is no server-side PIN: the first client to log in activates the
token with the PIN it supplies, and every other client must present that same
PIN before it is granted access. Authorization is open — any authenticated
client may use every operation.

Configuration comes from a YAML file (--config or ./pkcs11-proxy.yaml), the
PKCS11_PROXY_* environment, or flags, in that precedence order.`

const commandExamples = `  # Run with the example configuration
  pkcs11-proxy --config ./pkcs11-proxy.yaml

  # Insecure development listener configured only through the environment
  PKCS11_PROXY_INSECURE=true \
  PKCS11_PROXY_TARGET_MODULE=/opt/vendor/lib/libpkcs11.so \
  PKCS11_PROXY_TARGET_TOKEN_LABEL=mytoken \
    pkcs11-proxy --listen 127.0.0.1:9443`

func main() {
	var configFile string
	var listen string
	var insecure bool
	var devUI bool

	root := &cobra.Command{
		Use:     "pkcs11-proxy",
		Short:   "PKCS #11 proxy broker",
		Long:    commandDescription,
		Example: commandExamples,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadOptions(configFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("listen") {
				cfg.Listen = listen
			}
			if cmd.Flags().Changed("insecure") {
				cfg.Insecure = insecure
			}
			if cmd.Flags().Changed("dev-ui") {
				cfg.DevUI.Enabled = devUI
			}
			return run(cmd.Context(), cfg)
		},
	}
	root.Flags().StringVar(&configFile, "config", "", "YAML config file (default ./pkcs11-proxy.yaml)")
	root.Flags().StringVar(&listen, "listen", "", "override the configured listen address")
	root.Flags().BoolVar(&insecure, "insecure", false, "permit plaintext TCP (development only)")
	root.Flags().BoolVar(&devUI, "dev-ui", false, "serve the read-only dev dashboard (default 127.0.0.1:9463)")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.ExecuteContext(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg options) error {
	server, _, err := newServer(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()
	log.Printf("pkcs11-proxy: target %q revision %q listening on %s (insecure=%v)", cfg.Target.ID, cfg.Target.Revision, cfg.Listen, cfg.Insecure)
	if cfg.DevUI.Enabled {
		dashboard := newDevUI(server, cfg.Listen, map[string]string{cfg.Target.ID: cfg.Target.Revision})
		address, err := startDevUI(ctx, cfg.DevUI.Listen, cfg.DevUI.AllowRemote, dashboard)
		if err != nil {
			return err
		}
		log.Printf("pkcs11-proxy: dev dashboard at http://%s/dev/", address)
	}
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
