package softhsm

import (
	"testing"

	"github.com/otpki/pkcs11/vendortest"
)

func TestModuleContract(t *testing.T) {
	for _, module := range All() {
		vendortest.Module(t, module)
	}
}

func TestV2CompatibilityBehavior(t *testing.T) {
	definition := NewV2().Definition()
	if !definition.Behavior.RejectNullOutputProbe {
		t.Fatal("SoftHSM 2 must use a real output buffer for single-part sizing probes")
	}
}
