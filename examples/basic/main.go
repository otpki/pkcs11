package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

func main() {
	ctx := context.Background()

	// The managed client owns module initialization, token selection, login,
	// session pooling, retries, caching, and vendor-specific routing.
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		// `vendors/all` is convenient for examples and diagnostics. Production
		// services normally import only the one or two providers they expect.
		Vendors: all.Modules(),
		Token: pkcs11.TokenSelector{
			Label:        os.Getenv("PKCS11_TOKEN_LABEL"),
			SerialNumber: os.Getenv("PKCS11_TOKEN_SERIAL"),
		},
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
		PIN:   pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		Sessions: pkcs11.SessionConfig{
			MaxTotal: 4, // Bound all native handles owned by this client.
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("close PKCS#11 client: %v", err)
		}
	}()

	// These snapshots are safe to expose in diagnostics; they do not contain PINs
	// or key material.
	device := client.Device()
	log.Printf("module=%s interface=%d.%d token=%q vendor=%q",
		client.ModulePath(), client.Version().Major, client.Version().Minor,
		device.Fingerprint.Token.Label, client.Adapter().Name)

	// Health and validation are non-destructive. Validation additionally records
	// the live mechanism inventory and optionally tests the token RNG.
	health, err := client.Health(ctx, pkcs11.HealthOptions{CheckRandom: true})
	check(err)
	log.Printf("health=%s checks=%d", health.Status, len(health.Checks))

	randomBytes, err := client.Random(ctx, 32)
	check(err)
	tokenDigest, err := client.Digest(ctx, []byte("hashed inside the token"), pkcs11.DigestOptions{Hash: crypto.SHA256})
	check(err)
	log.Printf("random=%x digest=%x", randomBytes[:4], tokenDigest)

	// GenerateSigner creates a key pair and immediately adapts it to crypto.Signer.
	// A durable CKA_ID lets the client re-resolve stale object handles after recovery.
	signer, pair, err := client.GenerateSigner(ctx,
		pkcs11.KeyPairOptions{
			Algorithm: pkcs11.AlgorithmRSA,
			Label:     "example-rsa",
			ID:        []byte("example-rsa-v1"),
			RSABits:   3072,
			// TemplatePolicy applies deployment-wide metadata before explicit
			// PublicAttributes/PrivateAttributes are merged.
			TemplatePolicy: applicationTemplatePolicy("otpki-pkcs11-example"),
		},
		pkcs11.SignerConfig{DefaultHash: crypto.SHA256},
	)
	check(err)

	message := []byte("message signed by the HSM")
	digest := sha256.Sum256(message)
	// Sign implements crypto.Signer. For explicit routing, Client.Sign and
	// Signer.SignContext also accept pkcs11.SignatureOptions.
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	check(err)
	check(client.Verify(ctx, pair.Public, digest[:], signature, pkcs11.SignatureOptions{
		Algorithm:  pkcs11.AlgorithmRSA,
		Hash:       crypto.SHA256,
		Prehashed:  true,
		RSAPadding: pkcs11.RSAPaddingPKCS1v15,
	}))

	// The same RSA pair supports OAEP through both the managed API and the
	// crypto.Decrypter adapter.
	encryptedRSA, err := client.Encrypt(ctx, pair.Public, []byte("small secret"), pkcs11.CipherOptions{
		RSAPadding: pkcs11.RSAPaddingOAEP,
		Hash:       crypto.SHA256,
		OAEPLabel:  []byte("example-domain"),
	})
	check(err)
	decrypter, err := client.Decrypter(ctx, pair.Private, pair.Public)
	check(err)
	plaintext, err := decrypter.Decrypt(rand.Reader, encryptedRSA.Ciphertext, &rsa.OAEPOptions{
		Hash: crypto.SHA256, Label: []byte("example-domain"),
	})
	check(err)

	// Long-running processes usually locate durable objects created during a
	// previous run rather than generate new ones at startup.
	locatedPair, err := client.FindKeyPair(ctx, pkcs11.KeyLocator{ID: pair.Private.ID, Algorithm: pkcs11.AlgorithmRSA})
	check(err)
	locatedSigner, err := client.SignerFor(ctx, pkcs11.KeyLocator{ID: pair.Private.ID, Algorithm: pkcs11.AlgorithmRSA}, pkcs11.SignerConfig{DefaultHash: crypto.SHA256})
	check(err)
	locatedDecrypter, err := client.DecrypterFor(ctx, pkcs11.KeyLocator{ID: pair.Private.ID, Algorithm: pkcs11.AlgorithmRSA})
	check(err)
	log.Printf("located pair=%q signer-public=%T decrypter-public=%T", locatedPair.Private.Label, locatedSigner.Public(), locatedDecrypter.Public())

	// Secret-key algorithms use the same durable ObjectRef model.
	aesKey, err := client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmAES256, Label: "example-aes", ID: []byte("example-aes-v1"),
	})
	check(err)
	encryptedAES, err := client.Encrypt(ctx, aesKey, []byte("authenticated plaintext"), pkcs11.CipherOptions{
		Mode: pkcs11.CipherModeGCM, AAD: []byte("public metadata"),
	})
	check(err)
	decryptedAES, err := client.Decrypt(ctx, aesKey, encryptedAES.Ciphertext, pkcs11.CipherOptions{
		Mode: pkcs11.CipherModeGCM, IV: encryptedAES.IV, AAD: []byte("public metadata"),
	})
	check(err)

	// CBC and CTR are available through the same API when advertised by the token.
	// CBC mode applies PKCS#7 padding, CTR requires a complete 16-byte counter.
	iv, err := client.Random(ctx, 16)
	check(err)
	for _, mode := range []pkcs11.CipherMode{pkcs11.CipherModeCBC, pkcs11.CipherModeCTR} {
		result, err := client.Encrypt(ctx, aesKey, []byte("block mode plaintext"), pkcs11.CipherOptions{Mode: mode, IV: iv})
		check(err)
		value, err := client.Decrypt(ctx, aesKey, result.Ciphertext, pkcs11.CipherOptions{Mode: mode, IV: result.IV})
		check(err)
		log.Printf("AES %s plaintext=%q", mode, value)
	}

	hmacKey, err := client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmHMACSHA256, Label: "example-hmac", ID: []byte("example-hmac-v1"),
	})
	check(err)
	mac, err := client.MAC(ctx, hmacKey, message, pkcs11.MACOptions{})
	check(err)
	check(client.VerifyMAC(ctx, hmacKey, message, mac, pkcs11.MACOptions{}))

	// Search by durable attributes, then fetch and update selected metadata.
	found, err := client.FindOne(ctx, pkcs11.ObjectQuery{Label: "example-rsa", ID: []byte("example-rsa-v1")})
	check(err)
	allPairObjects, err := client.Find(ctx, pkcs11.ObjectQuery{ID: []byte("example-rsa-v1"), Limit: 10})
	check(err)
	attributes, err := client.Attributes(ctx, found,
		raw.NewAttribute(raw.CKA_LABEL, nil), raw.NewAttribute(raw.CKA_ID, nil))
	check(err)
	check(client.SetAttributes(ctx, aesKey, raw.NewAttribute(raw.CKA_LABEL, "example-aes-renamed")))
	aesKey.Label = "example-aes-renamed" // Keep the durable fallback locator current too.

	// Because the HSM signer implements crypto.Signer, it can be passed directly
	// to standard-library protocols such as X.509 certificate issuance.
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "otpki-pkcs11 example"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	check(err)
	certificate, err := x509.ParseCertificate(certificateDER)
	check(err)
	certificateRef, err := client.ImportCertificateForKey(ctx, certificate, pair.Public, pkcs11.CertificateImportOptions{
		Label: "example-certificate", ID: pair.Public.ID, ReplaceExisting: true,
	})
	check(err)
	certificates, err := client.FindCertificates(ctx, pkcs11.CertificateQuery{ID: pair.Public.ID})
	check(err)
	associatedCertificate, err := client.FindCertificateForKey(ctx, pair.Public)
	check(err)
	log.Printf("certificates=%d subject=%q", len(certificates), associatedCertificate.Certificate.Subject.CommonName)

	// AES key wrap is mechanism-explicit because wrapped formats are protocol
	// choices. CKA_EXTRACTABLE must be true on the wrapped key for most tokens.
	wrappablePolicy := pkcs11.DefaultSecretKeyPolicy()
	wrappablePolicy.Extractable = true
	wrappable, err := client.GenerateSecretKey(ctx, pkcs11.SecretKeyOptions{
		Algorithm: pkcs11.AlgorithmAES128, Label: "example-wrappable",
		Policy: &wrappablePolicy,
	})
	check(err)
	wrapped, err := client.Wrap(ctx, aesKey, wrappable, pkcs11.WrapOptions{
		Mechanism: raw.NewMechanism(raw.CKM_AES_KEY_WRAP_PAD, nil),
	})
	check(err)
	unwrapped, err := client.Unwrap(ctx, aesKey, wrapped, pkcs11.UnwrapOptions{
		Mechanism: raw.NewMechanism(raw.CKM_AES_KEY_WRAP_PAD, nil),
		Attributes: []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES),
			raw.NewAttribute(raw.CKA_TOKEN, true),
			raw.NewAttribute(raw.CKA_LABEL, "example-unwrapped"),
			raw.NewAttribute(raw.CKA_ENCRYPT, true),
			raw.NewAttribute(raw.CKA_DECRYPT, true),
		},
		Reference: pkcs11.ObjectRef{Class: raw.CKO_SECRET_KEY, KeyType: raw.CKK_AES, Algorithm: pkcs11.AlgorithmAES128, Label: "example-unwrapped"},
	})
	check(err)

	log.Printf("signature=%d rsa=%q aes=%q pair-objects=%d attributes=%d mac=%d",
		len(signature), plaintext, decryptedAES, len(allPairObjects), len(attributes), len(mac))

	// Destroy only objects created by this run. Production code commonly keeps
	// token objects and locates them later with SignerFor or DecrypterFor.
	for _, object := range []pkcs11.ObjectRef{certificateRef.Object, unwrapped, wrappable, hmacKey, aesKey, pair.Private, pair.Public} {
		if err := client.Destroy(ctx, object); err != nil {
			log.Printf("destroy %q: %v", object.Label, err)
		}
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("example failed: %w", err))
	}
}

type applicationTemplatePolicy string

func (application applicationTemplatePolicy) ApplyTemplate(_ pkcs11.TemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	return pkcs11.MergeAttributes(attributes, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_APPLICATION, string(application)),
	}), nil
}
