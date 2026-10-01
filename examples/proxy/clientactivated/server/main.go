// server publishes a client-activated Utimaco target. This process has
// no HSM PIN setting, no configuration field, environment lookup, or retained
// credential provider. The activating client supplies the PIN transiently.
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
		Address:       env("PKCS11_PROXY_ADDRESS", "127.0.0.1:9443"),
		AllowInsecure: true, // Development only; production should authenticate with mTLS.
		// Authentication establishes a stable workload principal before target
		// lookup or HSM capacity is consumed. This token is not the HSM PIN.
		Authenticator: workloadAuthenticator(os.Getenv("PKCS11_PROXY_AUTH_TOKEN")),
	}, proxy.TargetConfig{
		ID:       env("PKCS11_PROXY_ROUTE", "client-activated-utimaco"),
		Revision: env("PKCS11_PROXY_REVISION", "example-v1"),
		Client: pkcs11.Config{
			Module:  pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
			Token:   pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
			Vendors: []pkcs11.VendorModule{utimaco.New()},
			// Client.PIN must remain nil on every broker target.
		},
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
		},
		Login: proxy.LoginPolicy{
			// Selecting this mode explicitly is what permits an authorized remote
			// C_Login to perform the one target-wide physical activation.
			Mode:             proxy.PhysicalLoginClientActivated,
			PhysicalUserType: raw.CKU_USER,
			AllowedUserTypes: []uint{raw.CKU_USER},
			// There is deliberately no PhysicalPIN and no eager login.
			ActivationFailureCooldown: time.Second,
			// Every client login is audited before it can join activation. The PIN
			// slice is short-lived: never log, compare, hash, or retain it here.
			Authenticate: auditLogin,
		},
		// Authorization is separate from transport authentication and logical
		// login. It receives secret-free operation metadata only.
		Authorize: authorizeWorkload,
	})
	check(err)
	defer func() { check(server.Close(ctx)) }()

	log.Printf("client-activated proxy configured; server stores no HSM PIN")
	go reportActivation(ctx, server, env("PKCS11_PROXY_ROUTE", "client-activated-utimaco"))
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		check(err)
	}
}

func workloadAuthenticator(expected string) proxy.Authenticator {
	return func(_ context.Context, identity proxy.RequestIdentity) (string, error) {
		if expected == "" || subtle.ConstantTimeCompare(identity.Auth, []byte(expected)) != 1 {
			return "", errors.New("invalid workload credential")
		}
		return "example-pki-workload", nil
	}
}

func auditLogin(_ context.Context, attempt proxy.LoginAttempt) error {
	// Audit only non-secret facts. In particular, never inspect or retain
	// attempt.PIN; the proxy wipes this callback's copy after return.
	log.Printf("login requested principal=%q user-type=%d", attempt.Identity.Principal, attempt.UserType)
	return nil
}

func authorizeWorkload(_ context.Context, request proxy.AuthorizationRequest) error {
	if request.Identity.Principal != "example-pki-workload" {
		return fmt.Errorf("principal is not permitted on target %q", request.Target)
	}
	if request.PhysicalActivation {
		// This branch runs only for the leader selected to submit its PIN to the
		// inactive HSM. Followers never receive activation authority.
		if request.Operation != proxy.AuthorizationOperationActivateTarget {
			return fmt.Errorf("unexpected activation operation %q", request.Operation)
		}
		log.Printf("physical activation authorized principal=%q", request.Identity.Principal)
		return nil
	}

	// Deny destructive administration independently of ordinary HSM access.
	switch request.Operation {
	case "InitToken", "InitPIN", "SetPIN":
		return errors.New("token administration is not permitted")
	default:
		return nil
	}
}

func reportActivation(ctx context.Context, server *proxy.Server, route string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if stats, ok := server.TargetStats(route); ok {
				// ActivationStatus contains state, generation, principal, and times;
				// it never contains the PIN or a verifier derived from it.
				log.Printf("activation=%s generation=%d by=%q", stats.Activation.State, stats.Activation.Generation, stats.Activation.ActivatedBy)
			}
		}
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
		log.Fatal(fmt.Errorf("client-activated proxy server failed: %w", err))
	}
}
