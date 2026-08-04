package utimaco

import (
	"github.com/otpki/pkcs11/vendortest"
	"testing"
)

func TestModuleContract(t *testing.T) { vendortest.Module(t, New()) }
