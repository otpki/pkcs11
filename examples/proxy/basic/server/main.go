// server publishes one local PKCS #11 token through the bounded Go
// proxy. This development example uses plaintext localhost. production must use
// mTLS and a stable Authorizer as described in PROXY.md.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/utimaco"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := proxy.NewServer(ctx, proxy.ServerConfig{
		Address:        env("PKCS11_PROXY_ADDRESS", "127.0.0.1:9443"),
		AllowInsecure:  true, // Development only: use ServerConfig.TLS in production.
		MaxConnections: 128,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
	}, proxy.TargetConfig{
		ID:       env("PKCS11_PROXY_ROUTE", "example-hsm"),
		Revision: env("PKCS11_PROXY_REVISION", "example-v1"),
		Client: pkcs11.Config{
			Module: pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
			Token:  pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
			// The broker needs the same provider module for physical session/login
			// behavior and any broker-side vendor parameter codecs.
			Vendors: []pkcs11.VendorModule{utimaco.New()},
		},
		// This is the authoritative budget shared by every remote application.
		Sessions: proxy.SessionBudget{
			MaxPhysicalTotal:            8,
			MaxPhysicalReadWrite:        4,
			ReservedControlSessions:     1,
			MaxPinned:                   2,
			MaxQueued:                   64,
			MaxClients:                  256,
			MaxVirtualSessionsTotal:     1024,
			MaxVirtualSessionsPerClient: 16,
			MaxObjectsPerClient:         1024,
			QueueTimeout:                5 * time.Second,
			VirtualSessionIdleTimeout:   10 * time.Minute,
			PinnedOperationIdleTimeout:  time.Minute,
			ClientIdleTimeout:           15 * time.Minute,
			DedupEntries:                2048,
			DedupMaximumBytes:           32 << 20,
			DedupTTL:                    5 * time.Minute,
		},
		Login: proxy.LoginPolicy{
			// The broker alone receives and uses the real physical HSM PIN.
			PhysicalPIN:        pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
			PhysicalUserType:   raw.CKU_USER,
			AllowedUserTypes:   []uint{raw.CKU_USER},
			EagerPhysicalLogin: true,
			// Remote clients present a separate logical activation secret. A real
			// deployment normally validates a workload token or trusts verified mTLS.
			Authenticate: logicalAuthenticator(os.Getenv("PKCS11_PROXY_CLIENT_PIN")),
		},
	})
	check(err)
	defer func() { check(server.Close(ctx)) }()

	log.Printf("listening=%s routes=%v", server.Addr(), server.TargetIDs())
	go func() {
		for ticker := time.NewTicker(30 * time.Second); ; {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				stats, _ := server.TargetStats(env("PKCS11_PROXY_ROUTE", "example-hsm"))
				log.Printf("proxy capacity=%+v", stats)
			}
		}
	}()

	// Serve blocks until the signal context is canceled.
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		check(err)
	}
}

func logicalAuthenticator(expected string) proxy.LogicalAuthenticator {
	return func(_ context.Context, attempt proxy.LoginAttempt) error {
		if expected == "" || subtle.ConstantTimeCompare(attempt.PIN, []byte(expected)) != 1 {
			return errors.New("logical activation denied")
		}
		return nil
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("proxy server failed: %w", err))
	}
}
