package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config := pkcs11.DefaultDetectionConfig()
	// Supplying explicit paths is safer and gives deterministic preference.
	if path := os.Getenv("PKCS11_MODULE"); path != "" {
		config.ExplicitPaths = []string{path}
	}
	// ModuleCandidates only builds the ordered path list; it does not load any
	// native code. Use it to preview discovery policy safely.
	candidates, err := pkcs11.ModuleCandidates(config, all.Modules()...)
	if err != nil {
		panic(err)
	}
	log.Printf("discovery produced %d candidate paths", len(candidates))
	probes, err := pkcs11.DetectModules(ctx, config, all.Modules()...)
	if err != nil {
		panic(err)
	}
	output, err := json.MarshalIndent(probes, "", "  ")
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(output)       //nolint:errcheck
	os.Stdout.Write([]byte("\n")) //nolint:errcheck

	// DetectModules probes every candidate and returns failures
	// alongside successes. OpenDetected tries candidates in deterministic order
	// and returns the first usable module matching the token selector.
	client, err := pkcs11.OpenDetected(ctx, pkcs11.Config{
		Token: pkcs11.TokenSelector{
			Label:        os.Getenv("PKCS11_TOKEN_LABEL"),
			SerialNumber: os.Getenv("PKCS11_TOKEN_SERIAL"),
		},
		PIN:     pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		Vendors: all.Modules(),
	}, config)
	if err != nil {
		log.Printf("no detected module was opened: %v", err)
		return
	}
	defer func() { _ = client.Close(ctx) }() // handle the error in a long-running service
	log.Printf("opened detected module=%s vendor=%s", client.ModulePath(), client.Adapter().Name)
}
