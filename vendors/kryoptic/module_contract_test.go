package kryoptic

import (
	"testing"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendortest"
)

func TestModuleContract(t *testing.T) {
	vendortest.Module(t, New())
	if scope := New().Definition().Behavior.LoginScope; scope != pkcs11.VendorLoginSession {
		t.Fatalf("login scope = %v, want session", scope)
	}
}
