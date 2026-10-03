package all_test

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	vendorall "github.com/otpki/pkcs11/vendors/all"
)

func TestEveryShippedModuleHasAValidDefinition(t *testing.T) {
	modules := vendorall.Modules()
	if len(modules) == 0 {
		t.Fatal("aggregate vendor set is empty")
	}
	if _, err := pkcs11.VendorModules(modules...); err != nil {
		t.Fatal(err)
	}
}
