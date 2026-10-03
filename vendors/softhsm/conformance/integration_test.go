package conformance

import (
	"testing"

	base "github.com/otpki/pkcs11/conformance"
	"github.com/otpki/pkcs11/vendors/softhsm"
)

func TestConformance(t *testing.T) {
	base.Test(t, Profile(), base.WithVendorModules(softhsm.NewV2()))
}
