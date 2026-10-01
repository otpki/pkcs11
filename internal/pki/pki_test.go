package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTreeRoundTripAndWrite(t *testing.T) {
	ca, err := GenerateCA("dev CA", 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.IssueServer("broker", []string{"10.0.0.5", "broker.internal"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.IssueClient("alice", 0)
	if err != nil {
		t.Fatal(err)
	}
	tree := &Tree{CA: ca, Server: server, Clients: []*Issued{client}}
	files := tree.Files()
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key", "clients/alice.pem", "clients/alice.key"} {
		if len(files[name]) == 0 {
			t.Fatalf("missing %s in tree files", name)
		}
	}

	dir := t.TempDir()
	written, err := WriteTree(dir, tree, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 6 {
		t.Fatalf("wrote %d files", len(written))
	}
	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %o", info.Mode().Perm())
	}
	// Refuse clobber without force.
	if _, err := WriteTree(dir, tree, false); err == nil {
		t.Fatal("overwrite without force succeeded")
	}
	if _, err := WriteTree(dir, tree, true); err != nil {
		t.Fatalf("overwrite with force: %v", err)
	}

	// Reload CA from disk and issue again — the second-generation cert must
	// chain to the same root.
	reloaded, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	extra, err := reloaded.IssueClient("bob", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Verify leaf chains and SAN shape.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("CA PEM did not parse")
	}
	serverBlock, _ := pem.Decode(server.CertPEM)
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "broker.internal"}); err != nil {
		t.Fatalf("server cert does not verify: %v", err)
	}
	if len(serverCert.IPAddresses) != 1 || serverCert.IPAddresses[0].String() != "10.0.0.5" {
		t.Fatalf("IP SAN = %v", serverCert.IPAddresses)
	}
	clientBlock, _ := pem.Decode(extra.CertPEM)
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client cert does not verify: %v", err)
	}
	if clientCert.Subject.CommonName != "bob" {
		t.Fatalf("client CN = %q", clientCert.Subject.CommonName)
	}
	// The TLS stack must accept the generated pair.
	if _, err := tls.X509KeyPair(server.CertPEM, server.KeyPEM); err != nil {
		t.Fatalf("server pair rejected by tls: %v", err)
	}
	fp, err := Fingerprint(client)
	if err != nil || len(fp) != 32 || strings.Trim(fp, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}
