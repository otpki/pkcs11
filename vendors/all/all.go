// Package all returns every vendor module shipped with this repository.
//
// Applications that prefer a smaller trusted surface should import individual
// vendor packages and pass only the modules they expect to Config.Vendors.
package all

import (
	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/vendors/awscloudhsm"
	"github.com/otpki/pkcs11/vendors/azure"
	"github.com/otpki/pkcs11/vendors/crypto4a"
	"github.com/otpki/pkcs11/vendors/fortanix"
	"github.com/otpki/pkcs11/vendors/googlekms"
	"github.com/otpki/pkcs11/vendors/ibm"
	"github.com/otpki/pkcs11/vendors/kryoptic"
	"github.com/otpki/pkcs11/vendors/nshield"
	"github.com/otpki/pkcs11/vendors/opensc"
	"github.com/otpki/pkcs11/vendors/p11kit"
	"github.com/otpki/pkcs11/vendors/securosys"
	"github.com/otpki/pkcs11/vendors/smartcardhsm"
	"github.com/otpki/pkcs11/vendors/softhsm"
	"github.com/otpki/pkcs11/vendors/thales"
	"github.com/otpki/pkcs11/vendors/utimaco"
	"github.com/otpki/pkcs11/vendors/yubihsm"
)

// Modules constructs a fresh immutable module set. The returned slice may be
// modified by the caller without affecting later calls.
func Modules() []pkcs11.VendorModule {
	var modules []pkcs11.VendorModule
	modules = append(modules, utimaco.Modules()...)
	modules = append(modules, thales.All()...)
	modules = append(modules, softhsm.All()...)
	modules = append(modules,
		crypto4a.New(), nshield.New(), awscloudhsm.New(), securosys.New(),
		ibm.New(), kryoptic.New(), googlekms.New(), fortanix.New(), azure.New(), yubihsm.New(),
		smartcardhsm.New(), p11kit.New(), opensc.New(),
	)
	return modules
}
