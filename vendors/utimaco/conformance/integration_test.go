package conformance

import (
	"os"
	"strings"
	"testing"

	base "github.com/otpki/pkcs11/conformance"
	"github.com/otpki/pkcs11/vendors/utimaco"
)

// TestConformance runs inside the licensed fixture container. The entrypoint
// sets UTIMACO_PROFILE to select the GP (classical) or QuantumProtect (PQC)
// suite. QuantumProtect vendor-defined mechanisms are never enumerated through
// Cryptoki, so the QP profile must declare the firmware explicitly, matching
// the legacy proxy's pqc_firmware flag.
func TestConformance(t *testing.T) {
	var options []utimaco.Option
	if strings.EqualFold(os.Getenv("UTIMACO_PROFILE"), "qp") {
		options = append(options, utimaco.WithQuantumProtect())
	}
	base.Test(t, Profile(), base.WithVendorModules(utimaco.New(options...)))
}
