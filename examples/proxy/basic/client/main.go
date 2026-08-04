// client demonstrates both supported proxy consumers: the managed
// pkcs11.Client and the complete low-level raw.Module interface.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/utimaco"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	utimacoVendor := utimaco.New()
	target := proxy.Target{
		ConfigID:          "example-database-row",
		Revision:          env("PKCS11_PROXY_REVISION", "example-v1"),
		Endpoint:          env("PKCS11_PROXY_ENDPOINT", "127.0.0.1:9443"),
		Route:             env("PKCS11_PROXY_ROUTE", "example-hsm"),
		SecurityContextID: "insecure-local-development-v1",
		AllowInsecure:     true, // Development only: set TLS for production.
		ConnectTimeout:    3 * time.Second,
		RequestTimeout:    30 * time.Second,
		MaxAttempts:       2,
		// The source passes this module into the managed client automatically.
		// Utimaco parameters are byte records, so no custom proxy codec is needed.
		Vendors: []pkcs11.VendorModule{utimacoVendor},
	}

	// RemoteModule implements ModuleSource, so the normal managed API needs no
	// proxy-specific cryptographic code. Target.Vendors are carried automatically.
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(target),
		Token:  pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Login:  pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
		// This is a logical proxy credential, never the broker's physical HSM PIN.
		PIN: pkcs11.StaticPIN(os.Getenv("PKCS11_PROXY_CLIENT_PIN")),
	})
	check(err)
	digest, err := client.Digest(ctx, []byte("remote managed operation"), pkcs11.DigestOptions{Hash: crypto.SHA256})
	check(err)
	log.Printf("managed remote module=%s vendor=%s digest=%x", client.ModulePath(), client.Adapter().Family, digest)

	// Resolve shows whether the remote token selected the PKCS #11 3.2 standard
	// route or Utimaco's QuantumProtect fallback. The application still expresses
	// only algorithm intent and never hard-codes a vendor mechanism number.
	route, err := client.Resolve(pkcs11.Intent{Operation: pkcs11.OperationGenerate, Algorithm: pkcs11.AlgorithmMLDSA65})
	check(err)
	log.Printf("ML-DSA route source=%s mechanism=0x%x reasons=%v",
		route.MechanismSource, route.Mechanism.Mechanism, route.Reasons)

	signer, pair, err := client.GenerateSigner(ctx, pkcs11.KeyPairOptions{
		Algorithm: pkcs11.AlgorithmMLDSA65,
		Label:     "proxy-utimaco-ml-dsa",
		ID:        []byte("proxy-utimaco-ml-dsa-v1"),
	}, pkcs11.SignerConfig{})
	check(err)
	message := []byte("Utimaco vendor-routed signature over the proxy")
	signatureOptions := pkcs11.PQCDirect(nil, pkcs11.HedgePreferred)
	signature, err := signer.Sign(rand.Reader, message, signatureOptions)
	check(err)
	check(client.Verify(ctx, pair.Public, message, signature, signatureOptions))
	log.Printf("Utimaco ML-DSA signature=%d bytes", len(signature))
	check(client.Destroy(ctx, pair.Private))
	check(client.Destroy(ctx, pair.Public))
	check(client.Close())

	// proxy.Open returns a proxy.Client implementing every raw.Module method.
	// Direct raw consumers explicitly initialize, select slots, and own sessions.
	module, err := proxy.Open(ctx, target)
	check(err)
	defer func() { check(module.Close()) }()
	check(module.Initialize())
	defer func() { check(module.Finalize()) }()
	slots, err := module.GetSlotList(true)
	check(err)
	if len(slots) == 0 {
		log.Fatal("remote target has no token-present slots")
	}
	session, err := module.OpenSession(slots[0], raw.CKF_SERIAL_SESSION)
	check(err)
	defer func() { check(module.CloseSession(session)) }()
	check(module.Login(session, raw.CKU_USER, []byte(os.Getenv("PKCS11_PROXY_CLIENT_PIN"))))
	defer func() { check(module.Logout(session)) }()
	value, err := module.GenerateRandom(session, 16)
	check(err)
	log.Printf("raw remote interface=%+v random=%x", module.Interface(), value)
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
