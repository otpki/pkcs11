// client connects to pkcs11-proxy using client-activated login. The first
// successful caller activates the HSM. Later clients must present the same PIN.
//
// Environment:
//
//	PKCS11_PROXY_ENDPOINT   broker address            (default 127.0.0.1:9443)
//	PKCS11_PROXY_ROUTE      target route              (default hsm)
//	PKCS11_PROXY_REVISION   target revision           (default v1)
//	PKCS11_PROXY_AUTH_TOKEN workload identifier       (required, not the PIN)
//	PKCS11_PIN              the real HSM user PIN     (required)
//	PKCS11_TOKEN_LABEL      expected token label      (optional)
package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/vendors/all"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	target := proxy.Target{
		ConfigID:          "pinauth-example",
		Revision:          env("PKCS11_PROXY_REVISION", "v1"),
		Endpoints:         strings.Split(env("PKCS11_PROXY_ENDPOINTS", env("PKCS11_PROXY_ENDPOINT", "127.0.0.1:9443")), ","),
		Route:             env("PKCS11_PROXY_ROUTE", "hsm"),
		SecurityContextID: "pinauth-example-v1",
		AllowInsecure:     true, // Development only; configure TLS for production.
		// Vendor modules must mirror the broker's: the describe handshake
		// requires the client's parameter codec set to match exactly.
		Vendors: all.Modules(),
		// The workload token identifies this application to the proxy. It is not
		// the HSM PIN: the broker hashes it to derive a stable principal, so two
		// workloads cannot claim each other's pending activation. Any non-empty
		// process-scoped value works in this example; production should prefer
		// mTLS or a real workload credential.
		Auth: func(context.Context) ([]byte, error) {
			token := os.Getenv("PKCS11_PROXY_AUTH_TOKEN")
			if token == "" {
				return nil, errors.New("PKCS11_PROXY_AUTH_TOKEN is required")
			}
			return []byte(token), nil
		},
	}

	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(target),
		Token:  pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Login: pkcs11.LoginConfig{
			// Manual mode makes the activation boundary explicit: nothing logs
			// in until Activate below.
			Mode: pkcs11.LoginManual,
			Role: pkcs11.UserRoleUser,
		},
		// Only this client process reads PKCS11_PIN. The Secret is sent inside
		// C_Login, consumed by physical activation when this caller leads, and
		// wiped on both sides. The broker retains only an in-memory digest of
		// the activating PIN for verifying later clients.
		PIN: hsmPIN,
	})
	check(err)
	defer func() { check(client.Close(ctx)) }()

	// Activate performs the logical login. If the target is inactive this
	// caller may become the activation leader whose PIN reaches the HSM;
	// otherwise the PIN is verified against the activating PIN's digest and a
	// mismatch fails with CKR_PIN_INCORRECT.
	check(client.Activate(ctx))
	log.Printf("authenticated; remote token vendor=%s", client.Adapter().Family)

	// An ordinary managed operation proves the grant works.
	digest, err := client.Digest(ctx, []byte("authenticated through pkcs11-proxy"), pkcs11.DigestOptions{Hash: crypto.SHA256})
	check(err)
	log.Printf("digest=%x", digest)
}

func hsmPIN(context.Context, pkcs11.PINRequest) (pkcs11.Secret, error) {
	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		return pkcs11.Secret{}, errors.New("PKCS11_PIN is required")
	}
	return pkcs11.NewSecret([]byte(pin)), nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("proxy client failed: %w", err))
	}
}
