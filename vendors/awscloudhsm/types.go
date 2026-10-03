package awscloudhsm

import (
	"cmp"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// GCMParameters constructs the parameter structure expected by the CloudHSM
// generated-IV AES-GCM mechanism. The module rewrites the IV fields to the
// provider-required null-pointer form before the operation crosses the ABI.
func GCMParameters(aad []byte, tagBits uint) *raw.GCMParams {
	tagBits = cmp.Or(tagBits, 128)
	return &raw.GCMParams{AAD: slices.Clone(aad), TagBits: tagBits}
}
