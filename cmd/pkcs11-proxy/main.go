//go:generate go run . docs ../../docs/cli

// Command pkcs11-proxy runs the public-vendor proxy broker.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/otpki/pkcs11/proxycmd"
)

// Stamped with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := proxycmd.New(proxycmd.Options{Version: version}).ExecuteContext(ctx)
	stop()
	if err != nil {
		slog.Error("pkcs11-proxy failed", "error", err)
		os.Exit(1)
	}
}
