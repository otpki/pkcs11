// Package conformance owns the container fixtures for the SoftHSM vendor
// module. Keeping these definitions beside the module means the central
// launcher has no SoftHSM-specific paths or startup policy.
package conformance

import (
	"time"

	"github.com/otpki/pkcs11/conformance/containerfixture"
)

// Fixtures returns the public SoftHSM conformance runtimes shipped by this
// repository. SoftHSM 2 is the portable baseline for the PKCS #11 3.x suite.
func Fixtures() []containerfixture.Fixture {
	return []containerfixture.Fixture{
		containerfixture.New(containerfixture.Definition{
			ID:           "softhsm2",
			Dockerfile:   "vendors/softhsm/conformance/docker/Dockerfile",
			Timeout:      35 * time.Minute,
			IncludeInAll: true,
		}),
	}
}
