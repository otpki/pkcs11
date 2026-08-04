// client authenticates to the proxy with a workload credential, then
// supplies the real HSM PIN only through the managed activation call.
package main

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/vendors/utimaco"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	target := proxy.Target{
		ConfigID:          "client-owned-hsm-credential",
		Revision:          env("PKCS11_PROXY_REVISION", "example-v1"),
		Endpoint:          env("PKCS11_PROXY_ENDPOINT", "127.0.0.1:9443"),
		Route:             env("PKCS11_PROXY_ROUTE", "client-activated-utimaco"),
		SecurityContextID: "example-workload-auth-v1",
		AllowInsecure:     true, // Development only; use mTLS in production.
		// Auth authenticates this workload to the proxy. It is deliberately
		// separate from the HSM PIN passed to pkcs11.Config.PIN below.
		Auth: func(context.Context) ([]byte, error) {
			return []byte(os.Getenv("PKCS11_PROXY_AUTH_TOKEN")), nil
		},
		Vendors: []pkcs11.VendorModule{utimaco.New()},
	}

	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(target),
		Token:  pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Login: pkcs11.LoginConfig{
			// Manual mode makes the audited activation boundary explicit.
			Mode: pkcs11.LoginManual,
			Role: pkcs11.UserRoleUser,
		},
		// Only this client process reads PKCS11_PIN. The returned Secret is sent
		// by C_Login, used for physical activation if this caller is selected as
		// leader, and wiped by both managed client and proxy paths.
		PIN: auditedHSMCredential,
	})
	check(err)
	defer func() { check(client.Close()) }()

	// Activate obtains a fresh PIN and performs logical login. If the target is
	// inactive, one authorized caller becomes the physical activation leader.
	check(client.Activate(ctx))
	log.Printf("activated remote token vendor=%s", client.Adapter().Family)

	// Normal managed operations now use the generation-bound logical grant.
	// This digest is simple and non-destructive; private key operations use the
	// same authorization and activation state.
	digest, err := client.Digest(ctx, []byte("client-activated proxy operation"), pkcs11.DigestOptions{Hash: crypto.SHA256})
	check(err)
	log.Printf("remote digest=%x", digest)

	// A private token object proves that the generation-bound login grant is in
	// effect. TargetConfig.Authorize sees GenerateKey, Sign, and DestroyObject as
	// separate secret-free authorization requests on the server.
	hmacKey, err := client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmHMACSHA256,
		Label:     "client-activated-example-hmac",
		ID:        []byte("client-activated-example-hmac-v1"),
	})
	check(err)
	mac, err := client.MAC(ctx, hmacKey, []byte("authorized private operation"), pkcs11.MACOptions{})
	check(err)
	log.Printf("remote HMAC=%x", mac)
	check(client.Destroy(ctx, hmacKey))

	// If a later private operation returns proxy.ErrActivationRequired, obtain a
	// freshly approved PIN and call Activate again. No old PIN exists on the server
	// for transparent recovery after HSM, module, or control-session loss.
}

func auditedHSMCredential(_ context.Context, request pkcs11.PINRequest) (pkcs11.Secret, error) {
	log.Printf("HSM PIN approved purpose=%s token=%q attempt=%d", request.Purpose, request.Token.Label, request.Attempt)
	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		return nil, fmt.Errorf("PKCS11_PIN is required in the client process")
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
		log.Fatal(fmt.Errorf("client-activated proxy client failed: %w", err))
	}
}
