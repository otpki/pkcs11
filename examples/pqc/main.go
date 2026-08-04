package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"log"
	"os"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

func main() {
	ctx := context.Background()
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module:  pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		Vendors: all.Modules(),
		Token: pkcs11.TokenSelector{
			Label: os.Getenv("PKCS11_TOKEN_LABEL"),
		},
		Login: pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
		PIN:   pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close() //nolint:errcheck

	signer, pair, err := client.GenerateSigner(ctx,
		pkcs11.KeyPairOptions{
			Algorithm: pkcs11.AlgorithmMLDSA65,
			Label:     "example-ml-dsa-65",
			ID:        []byte("example-ml-dsa-65-v1"),
			PrivateAttributes: []*raw.Attribute{
				raw.NewAttribute(raw.CKA_ALWAYS_AUTHENTICATE, true),
			},
		},
		pkcs11.SignerConfig{},
	)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("message signed directly by ML-DSA")
	signature, err := signer.SignContext(ctx, message, pkcs11.PQCDirect(nil, pkcs11.HedgePreferred))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("public ID=%x signature bytes=%d", pair.Public.ID, len(signature))
	if err := client.Verify(ctx, pair.Public, message, signature, pkcs11.PQCDirect(nil, pkcs11.HedgePreferred)); err != nil {
		log.Fatal(err)
	}

	// ML-DSA also supports external prehash plus a domain-separation context.
	// The supplied digest and crypto.Hash must agree.
	prehash := sha256.Sum256(message)
	prehashOptions := pkcs11.PQCPrehash(crypto.SHA256, []byte("example-context"), pkcs11.HedgePreferred)
	prehashSignature, err := signer.SignContext(ctx, prehash[:], prehashOptions)
	if err != nil {
		log.Fatal(err)
	}
	if err := client.Verify(ctx, pair.Public, prehash[:], prehashSignature, prehashOptions); err != nil {
		log.Fatal(err)
	}

	// ML-KEM returns the ciphertext in Go memory and keeps both shared secrets in
	// the token. This example makes them extractable only so it can compare them.
	// real applications should leave the default sensitive policy unchanged and
	// use the secret in a subsequent token operation instead.
	kemPair, err := client.GenerateKeyPair(ctx, pkcs11.KeyPairOptions{
		Algorithm: pkcs11.AlgorithmMLKEM768,
		Label:     "example-ml-kem-768",
		ID:        []byte("example-ml-kem-768-v1"),
	})
	if err != nil {
		log.Fatal(err)
	}
	exportable := pkcs11.DefaultSecretKeyPolicy()
	exportable.Token = true
	exportable.Extractable = true
	encapsulation, err := client.Encapsulate(ctx, kemPair.Public, pkcs11.KEMOptions{
		Algorithm:    pkcs11.AlgorithmMLKEM768,
		Label:        "example-encapsulated-secret",
		SecretPolicy: &exportable,
	})
	if err != nil {
		log.Fatal(err)
	}
	decapsulated, err := client.Decapsulate(ctx, kemPair.Private, encapsulation.Ciphertext, pkcs11.KEMOptions{
		Algorithm:    pkcs11.AlgorithmMLKEM768,
		Label:        "example-decapsulated-secret",
		SecretPolicy: &exportable,
	})
	if err != nil {
		log.Fatal(err)
	}
	left, err := client.ExportValue(ctx, encapsulation.Secret)
	if err != nil {
		log.Fatal(err)
	}
	right, err := client.ExportValue(ctx, decapsulated)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ML-KEM ciphertext=%d shared-secrets-match=%t", len(encapsulation.Ciphertext), bytes.Equal(left, right))
	for _, object := range []pkcs11.ObjectRef{
		decapsulated, encapsulation.Secret, kemPair.Private, kemPair.Public, pair.Private, pair.Public,
	} {
		if err := client.Destroy(ctx, object); err != nil {
			log.Printf("destroy %q: %v", object.Label, err)
		}
	}

	// Vendor-provided external mu mode uses SignatureOptions{ExternalMu: true}
	// and requires an adapter alias named "ml-dsa-external-mu".
	// Stateful HSS/LMS/XMSS/XMSSMT keys use KeyPairOptions.ParameterSet or HSS;
	// query their remaining one-time signatures with client.HSSKeysRemaining.
}
