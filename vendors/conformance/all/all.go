// Package all returns every vendor-specific conformance extension and
// container fixture shipped with this repository. Production applications do
// not need this package.
package all

import (
	"github.com/otpki/pkcs11/conformance/containerfixture"
	kryopticconformance "github.com/otpki/pkcs11/vendors/kryoptic/conformance"
	softhsmconformance "github.com/otpki/pkcs11/vendors/softhsm/conformance"
	utimacoconformance "github.com/otpki/pkcs11/vendors/utimaco/conformance"
)

// Fixtures constructs every containerized provider runtime. Each fixture owns
// its Dockerfile, external assets, licensed-file preparation, and default
// timeout; the Testcontainers launcher only orchestrates the returned interface.
func Fixtures() []containerfixture.Fixture {
	var result []containerfixture.Fixture
	result = append(result, softhsmconformance.Fixtures()...)
	result = append(result, kryopticconformance.Fixtures()...)
	result = append(result, utimacoconformance.Fixtures()...)
	return result
}
