package thales

import (
	"testing"

	"github.com/otpki/pkcs11/vendortest"
)

func TestModuleContract(t *testing.T) {
	for _, module := range All() {
		vendortest.Module(t, module)
	}
}
