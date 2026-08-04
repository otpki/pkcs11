package main

import (
	"context"
	"log"
	"os"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/examples/customvendor/provider"
)

func main() {
	ctx := context.Background()
	module := provider.New()

	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module: pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		Token: pkcs11.TokenSelector{
			Label: os.Getenv("PKCS11_TOKEN_LABEL"),
		},
		PIN:     pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		Vendors: []pkcs11.VendorModule{module},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close() // handle this error in a production service

	log.Printf("selected vendor=%s token=%s", client.Adapter().Family, client.Device().Fingerprint.Token.Label)
}
