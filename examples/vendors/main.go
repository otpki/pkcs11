// vendors shows the supported vendor-module composition patterns.
// Vendor modules are ordinary Go values selected explicitly by the application.
// there is no side-effect registration or process-global plugin registry.
package main

import (
	"context"
	"log"
	"os"

	"github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendorkit"
	"github.com/otpki/pkcs11/vendors/all"
	"github.com/otpki/pkcs11/vendors/opensc"
)

func main() {
	ctx := context.Background()

	// Production applications should normally import only their expected
	// provider. This keeps the trusted compatibility and discovery surface small.
	openSC := opensc.New()

	// Decorate a shipped module when licensed/private SDK knowledge adds numeric
	// identifiers or metadata but does not change operational behavior.
	decorated := vendorkit.MustDecorate(openSC, func(definition *pkcs11.VendorDefinition) {
		definition.Source = "OpenSC public definitions plus application-reviewed policy"
		if definition.Catalog.Attributes == nil {
			definition.Catalog.Attributes = make(map[string]pkcs11.NumericID)
		}
		definition.Catalog.Attributes["application-example-attribute"] = 0x80000001
	})

	// VendorModules validates definitions and returns operator-friendly metadata
	// without loading a native library.
	metadata, err := pkcs11.VendorModules(decorated)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("configured vendor id=%s source=%s", metadata[0].Family, metadata[0].Source)

	client, err := pkcs11.Open(ctx, pkcs11.Config{
		Module:  pkcs11.LocalModule(os.Getenv("PKCS11_MODULE")),
		Token:   pkcs11.TokenSelector{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		PIN:     pkcs11.StaticPIN(os.Getenv("PKCS11_PIN")),
		Vendors: []pkcs11.VendorModule{decorated},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close(ctx) }() // handle the error in a production service
	log.Printf("selected vendor=%s variant=%s", client.Adapter().Family, client.Adapter().Variant)

	// Other valid composition choices:
	_ = []pkcs11.VendorModule{} // Standards-only; no vendor compatibility behavior.
	_ = all.Modules()           // Broad diagnostics and conformance tooling.

	// For completely new providers, see examples/customvendor. Its provider
	// package uses vendorkit.MustNew and can move into a separate Go module.
}
