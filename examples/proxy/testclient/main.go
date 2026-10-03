// testclient exercises a pkcs11-proxy running in --test mode. It lists routes,
// activates one with PIN "1234", and runs a digest.
//
// Start the broker with:
//
//	pkcs11-proxy serve --test --insecure --dev_ui.enabled
//
// then: go run ./examples/proxy/testclient
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
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
	defer func() {
		if r := recover(); r != nil {
			log.Fatal(r)
		}
	}()
	run()
}

func run() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// PKCS11_PROXY_ENDPOINTS may hold several comma-separated replicas; the
	// client pins whichever one rendezvous hashing selects for it.
	endpoints := strings.Split(env("PKCS11_PROXY_ENDPOINTS",
		env("PKCS11_PROXY_ENDPOINT", "127.0.0.1:9443")), ",")

	// Transport: PKCS11_PROXY_CA selects the trust root (e.g. pki/ca.pem from
	// `pkcs11-proxy pki init`); PKCS11_PROXY_CERT/_KEY present a client cert
	// for mTLS. Without them the client requires an --insecure broker.
	tlsConfig, allowInsecure := clientTLS()

	routes, err := proxy.ListRoutes(ctx, proxy.Target{
		Endpoints:         endpoints,
		TLS:               tlsConfig,
		AllowInsecure:     allowInsecure,
		SecurityContextID: "testclient-v1",
		Auth:              workloadToken,
	})
	check(err)
	for _, route := range routes {
		log.Printf("route=%q token=%q serial=%s slot=%d model=%s",
			route.ID, route.TokenLabel, route.TokenSerial, route.SlotID, route.Model)
	}
	if len(routes) == 0 {
		panic("broker advertised no routes — is it running with --test?")
	}

	route := env("PKCS11_PROXY_ROUTE", routes[0].ID)
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID:          "testclient",
			Revision:          "v1",
			Endpoints:         endpoints,
			Route:             route,
			SecurityContextID: "testclient-v1",
			TLS:               tlsConfig,
			AllowInsecure:     allowInsecure,
			Auth:              workloadToken,
			Vendors:           all.Modules(), // must match the broker's vendor set
		}),
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginManual, Role: pkcs11.UserRoleUser},
		PIN:   pkcs11.StaticPIN("1234"),
	})
	check(err)
	defer func() { check(client.Close(ctx)) }()

	check(client.Activate(ctx))
	log.Printf("activated route=%q token=%q", route, client.Device().Fingerprint.Token.Label)

	digest, err := client.Digest(ctx, []byte("test mode round trip"), pkcs11.DigestOptions{Hash: crypto.SHA256})
	check(err)
	log.Printf("digest=%x", digest)

	random, err := client.Random(ctx, 16)
	check(err)
	log.Printf("random=%x", random)
}

// clientTLS builds the transport config from PKCS11_PROXY_CA (trust root),
// PKCS11_PROXY_CERT and PKCS11_PROXY_KEY (optional client certificate for
// mTLS). Returns nil TLS config plus allowInsecure=true when no CA is given.
func clientTLS() (*tls.Config, bool) {
	caFile := os.Getenv("PKCS11_PROXY_CA")
	if caFile == "" {
		return nil, true
	}
	pemBytes, err := os.ReadFile(caFile)
	check(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		panic(fmt.Errorf("testclient: %s holds no PEM certificates", caFile))
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if certFile := os.Getenv("PKCS11_PROXY_CERT"); certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, os.Getenv("PKCS11_PROXY_KEY"))
		check(err)
		config.Certificates = []tls.Certificate{pair}
		log.Printf("mTLS client cert=%s", certFile)
	}
	return config, false
}

// workloadToken is the workload credential the broker's authenticator
// requires; any non-empty value is accepted by the test setup.
func workloadToken(context.Context) ([]byte, error) {
	return []byte(env("PKCS11_PROXY_AUTH_TOKEN", "testclient")), nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func check(err error) {
	if err != nil {
		panic(fmt.Errorf("testclient: %w", err))
	}
}
