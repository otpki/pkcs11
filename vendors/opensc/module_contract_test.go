package opensc

import (
	"testing"

	"github.com/otpki/pkcs11/vendortest"
)

func TestModuleContract(t *testing.T) {
	vendortest.Module(t, New())
}
