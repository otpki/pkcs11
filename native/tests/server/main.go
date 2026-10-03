// This process is a test fixture, not a second proxy command.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/otpki/pkcs11/proxycmd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	directory := flag.String("pki", "", "make short-lived mutual TLS credentials in this directory")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	settings := map[string]string{"endpoint": listener.Addr().String(), "route": "test-alpha"}
	if *directory != "" {
		config, files, err := testTLS(*directory)
		if err != nil {
			return err
		}
		listener = tls.NewListener(listener, config)
		maps.Copy(settings, files)
	}
	server, err := proxycmd.TestServer(ctx, listener, nil)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Close(cleanup)
	}()
	// One JSON line lets the parent discover the ephemeral listener and PEM paths.
	if err := json.NewEncoder(os.Stdout).Encode(settings); err != nil {
		return err
	}
	if err := server.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func testTLS(directory string) (*tls.Config, map[string]string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "native client test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	files := map[string]string{"ca_file": filepath.Join(directory, "ca.pem")}
	if err := os.WriteFile(files["ca_file"], caPEM, 0o600); err != nil {
		return nil, nil, err
	}
	var serverCertificate tls.Certificate
	for i, name := range []string{"server", "client"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if name == "server" {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			cert.DNSNames = []string{"localhost"}
			cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if name == "server" {
			serverCertificate, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return nil, nil, err
			}
		} else {
			files["cert_file"] = filepath.Join(directory, "client.pem")
			files["key_file"] = filepath.Join(directory, "client-key.pem")
			if err := os.WriteFile(files["cert_file"], certPEM, 0o600); err != nil {
				return nil, nil, err
			}
			if err := os.WriteFile(files["key_file"], keyPEM, 0o600); err != nil {
				return nil, nil, err
			}
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	}, files, nil
}
