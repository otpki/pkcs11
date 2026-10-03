// Package pki generates a small development mTLS tree for the PKCS #11 proxy:
// one self-signed Ed25519 CA plus server and client leaf certificates. It is
// deliberately simple — it exists so a broker's tls.cert_file /
// tls.client_ca_file material and client credentials can be produced without
// standing up a real CA. Generated keys stay in memory or land on disk with
// 0600 permissions; nothing here replaces a production CA.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	// DefaultCADays and DefaultLeafDays are convenient lifetimes for local
	// development certificates, not a public-CA or production policy.
	DefaultCADays   = 3650
	DefaultLeafDays = 825
)

// CA is a self-signed Ed25519 certificate authority. CertPEM is safe to
// distribute; KeyPEM must stay 0600.
type CA struct {
	cert    *x509.Certificate
	key     ed25519.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// Issued is one signed leaf certificate plus its private key. CertPEM carries
// the leaf followed by the issuing CA so it can be used directly as a TLS
// cert_file.
type Issued struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
}

var nameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SafeFileName maps a certificate CN to a filename-safe slug.
func SafeFileName(name string) string {
	clean := strings.Trim(nameSanitizer.ReplaceAllString(name, "-"), "-.")
	if clean == "" {
		return "cert"
	}
	return clean
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func pemKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pemBlock("PRIVATE KEY", der), nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return serial, nil
}

// GenerateCA creates a self-signed Ed25519 CA valid for the given number of
// days.
func GenerateCA(commonName string, days int) (*CA, error) {
	if days <= 0 {
		days = DefaultCADays
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"pkcs11-proxy dev"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          keyID(public),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, fmt.Errorf("pki: create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := pemKey(private)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: private, CertPEM: pemBlock("CERTIFICATE", der), KeyPEM: keyPEM}, nil
}

// LoadCA reads a PEM certificate and PKCS8 Ed25519 key, e.g. the files written
// by WriteTree, so later invocations can issue more leaves under the same CA.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // G304: certPath is an operator-supplied dev-PKI location.
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("pki: %s does not contain a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // G304: keyPath is an operator-supplied dev-PKI location.
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("pki: %s does not contain a PEM key", keyPath)
	}
	raw, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse %s: %w", keyPath, err)
	}
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pki: %s is not an Ed25519 private key", keyPath)
	}
	return &CA{cert: cert, key: key, CertPEM: pemBlock("CERTIFICATE", cert.Raw), KeyPEM: keyPEM}, nil
}

func keyID(public ed25519.PublicKey) []byte {
	digest := sha256.Sum256(public)
	return digest[:20]
}

// Issue signs one leaf certificate under the CA with the supplied template
// tweaks — the shared core of IssueServer and IssueClient.
func (ca *CA) issue(name string, days int, customize func(*x509.Certificate)) (*Issued, error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return nil, errors.New("pki: CA is not loaded")
	}
	if days <= 0 {
		days = DefaultLeafDays
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"pkcs11-proxy dev"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(public),
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}
	customize(template)
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: issue %q: %w", name, err)
	}
	keyPEM, err := pemKey(private)
	if err != nil {
		return nil, err
	}
	chain := append(pemBlock("CERTIFICATE", der), ca.CertPEM...)
	return &Issued{Name: name, CertPEM: chain, KeyPEM: keyPEM}, nil
}

// IssueServer signs a serverAuth leaf. Every entry of hosts becomes a SAN —
// literal IPs become IP SANs, everything else a DNS name.
func (ca *CA) IssueServer(name string, hosts []string, days int) (*Issued, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	return ca.issue(name, days, func(t *x509.Certificate) {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
				t.IPAddresses = append(t.IPAddresses, ip)
			} else {
				t.DNSNames = append(t.DNSNames, host)
			}
		}
	})
}

// IssueClient signs a clientAuth leaf; the CN is the workload identity a
// broker sees when tls.client_ca_file verification is on.
func (ca *CA) IssueClient(name string, days int) (*Issued, error) {
	return ca.issue(name, days, func(t *x509.Certificate) {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
}

// Tree is one generated PKI: the CA, an optional server leaf, and any client
// leaves. Files maps paths relative to the tree root onto PEM contents.
type Tree struct {
	CA      *CA
	Server  *Issued
	Clients []*Issued
}

// Files renders the tree as a path → PEM map (relative POSIX paths, matching
// the on-disk layout WriteTree produces). The DevUI returns this map
// verbatim; the CLI writes it to disk.
func (t *Tree) Files() map[string][]byte {
	files := map[string][]byte{
		"ca.pem": t.CA.CertPEM,
		"ca.key": t.CA.KeyPEM,
	}
	if t.Server != nil {
		files["server.pem"] = t.Server.CertPEM
		files["server.key"] = t.Server.KeyPEM
	}
	for _, client := range t.Clients {
		slug := SafeFileName(client.Name)
		files["clients/"+slug+".pem"] = client.CertPEM
		files["clients/"+slug+".key"] = client.KeyPEM
	}
	return files
}

// WriteTree writes the bundle under dir — certs 0644, keys 0600 — refusing to
// overwrite any existing file unless force is set.
func WriteTree(dir string, tree *Tree, force bool) ([]string, error) {
	return WriteFiles(dir, tree.Files(), force)
}

// WriteFiles writes a path → PEM map under dir. Names must be relative POSIX
// paths without traversal; .key suffixed files land 0600, the rest 0644.
func WriteFiles(dir string, files map[string][]byte, force bool) ([]string, error) {
	var written []string
	for _, name := range slices.Sorted(maps.Keys(files)) {
		content := files[name]
		clean := path.Clean(name)
		if clean != name || strings.HasPrefix(name, "..") || path.IsAbs(name) {
			return written, fmt.Errorf("pki: unsafe file name %q", name)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return written, err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			mode = 0o600
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		if !force {
			flags |= os.O_EXCL
		}
		file, err := os.OpenFile(target, flags, mode) //nolint:gosec // G304: target is an operator-supplied dev-PKI location.
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return written, fmt.Errorf("pki: %s exists (use --force to overwrite)", target)
			}
			return written, err
		}
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			return written, err
		}
		if err := file.Close(); err != nil {
			return written, err
		}
		written = append(written, target)
	}
	return written, nil
}

// Fingerprint is the stable hex digest a broker derives from a peer's leaf
// certificate — the workload identity mTLS principals are built on.
func Fingerprint(leaf *Issued) (string, error) {
	block, _ := pem.Decode(leaf.CertPEM)
	if block == nil {
		return "", fmt.Errorf("pki: %s cert did not decode", leaf.Name)
	}
	digest := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(digest[:16]), nil
}
