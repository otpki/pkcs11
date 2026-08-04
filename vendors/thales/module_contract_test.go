package thales

import (
	"github.com/otpki/pkcs11/vendortest"
	"testing"
)

func TestModuleContract(t *testing.T) {
	for _, module := range All() {
		vendortest.Module(t, module)
	}
}
