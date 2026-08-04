// signatures compares the main classical signing families. The same
// managed crypto.Signer surface works for RSA, ECDSA, and Edwards curves.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"os"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendors/all"
)

func main() {
	ctx := context.Background()
	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module:  pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		Token:   pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		PIN:     pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		Vendors: all.Modules(),
	})
	check(err)
	defer func() { check(client.Close()) }()

	message := []byte("one message, several HSM signature families")
	digest := sha256.Sum256(message)
	algorithms := []pkcs11.Algorithm{
		pkcs11.AlgorithmRSA,
		pkcs11.AlgorithmECDSAP256,
		pkcs11.AlgorithmEd25519,
	}
	for _, algorithm := range algorithms {
		signer, pair, err := client.GenerateSigner(ctx, pkcs11.KeyPairOptions{
			Algorithm: algorithm,
			Label:     "example-" + string(algorithm),
			ID:        []byte("example-" + string(algorithm) + "-v1"),
		}, pkcs11.SignerConfig{DefaultHash: crypto.SHA256})
		check(err)

		// RSA and ECDSA sign a digest. Ed25519 signs the complete message and uses
		// crypto.Hash(0), matching the standard crypto.Signer convention.
		input, options := digest[:], crypto.SignerOpts(crypto.SHA256)
		verify := pkcs11.SignatureOptions{Algorithm: algorithm, Hash: crypto.SHA256, Prehashed: true}
		if algorithm == pkcs11.AlgorithmEd25519 {
			input, options = message, crypto.Hash(0)
			verify = pkcs11.SignatureOptions{Algorithm: algorithm}
		}
		signature, err := signer.Sign(rand.Reader, input, options)
		check(err)
		check(client.Verify(ctx, pair.Public, input, signature, verify))
		log.Printf("algorithm=%s public=%T signature=%d", algorithm, signer.Public(), len(signature))

		check(client.Destroy(ctx, pair.Private))
		check(client.Destroy(ctx, pair.Public))
	}

	// Swap P-256 for P-384/P-521 or Ed25519 for Ed448 when supported. RSA-PSS
	// is selected with rsa.PSSOptions or pkcs11.SignatureOptions{RSAPadding: ...}.
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("signature example failed: %w", err))
	}
}
