// Package conformance owns the Kryoptic PKCS #11 3.x/PQC container fixture.
package conformance

import (
	"time"

	"github.com/otpki/pkcs11/conformance/containerfixture"
)

// Fixtures returns the public Kryoptic runtime used for standard PKCS #11 3.2
// and post-quantum conformance coverage.
func Fixtures() []containerfixture.Fixture {
	return []containerfixture.Fixture{
		containerfixture.New(containerfixture.Definition{
			ID:           "kryoptic-pqc",
			Dockerfile:   "vendors/kryoptic/conformance/docker/Dockerfile",
			Timeout:      120 * time.Minute,
			IncludeInAll: true,
		}),
	}
}
