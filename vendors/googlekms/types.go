package googlekms

import (
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// Algorithm is a Google Cloud KMS algorithm selector accepted by kmsp11.
type Algorithm uint

// ProtectionLevel is a Google Cloud KMS protection-level selector.
type ProtectionLevel uint

const (
	// AlgorithmRSAPSS2048SHA256 selects a 2048-bit RSA-PSS SHA-256 key.
	AlgorithmRSAPSS2048SHA256 Algorithm = 2
	// AlgorithmRSAPKCS12048SHA256 selects a 2048-bit RSA PKCS #1 v1.5 SHA-256 key.
	AlgorithmRSAPKCS12048SHA256 Algorithm = 5
	// AlgorithmRSAOAEP2048SHA256 selects a 2048-bit RSA-OAEP SHA-256 key.
	AlgorithmRSAOAEP2048SHA256 Algorithm = 8
	// AlgorithmECDSAP256SHA256 selects a P-256 ECDSA SHA-256 key.
	AlgorithmECDSAP256SHA256 Algorithm = 12
	// AlgorithmECDSAP384SHA384 selects a P-384 ECDSA SHA-384 key.
	AlgorithmECDSAP384SHA384 Algorithm = 13
	// AlgorithmAES256GCM selects a 256-bit AES-GCM key.
	AlgorithmAES256GCM Algorithm = 19
	// AlgorithmHMACSHA256 selects an HMAC-SHA-256 key.
	AlgorithmHMACSHA256 Algorithm = 32
)

// GenerateOptions builds the proprietary attributes used to create a Google
// Cloud KMS key through kmsp11. These attributes are intentionally kept in the
// vendor package rather than the vendor-neutral root API.
type GenerateOptions struct {
	Algorithm        Algorithm
	ProtectionLevel  ProtectionLevel
	CryptoKeyBackend string
}

// Attributes converts the options to a caller-owned PKCS #11 template fragment.
func (o GenerateOptions) Attributes() ([]*raw.Attribute, error) {
	if o.Algorithm == 0 {
		return nil, fmt.Errorf("googlekms: algorithm is required")
	}
	result := []*raw.Attribute{raw.NewAttribute(AttributeAlgorithm, uint(o.Algorithm))}
	if o.ProtectionLevel != 0 {
		result = append(result, raw.NewAttribute(AttributeProtectionLevel, uint(o.ProtectionLevel)))
	}
	if o.CryptoKeyBackend != "" {
		result = append(result, raw.NewAttribute(AttributeCryptoKeyBackend, o.CryptoKeyBackend))
	}
	return result, nil
}

// GCMParams creates a writable 12-byte IV buffer for kmsp11 generated-IV GCM.
func GCMParams(aad []byte, tagBits uint) *raw.GCMParams {
	if tagBits == 0 {
		tagBits = 128
	}
	return &raw.GCMParams{
		IV:      make([]byte, 12),
		IVBits:  96,
		AAD:     append([]byte(nil), aad...),
		TagBits: tagBits,
	}
}

// ObjectAttributes asks discovery to retain the proprietary key metadata used
// by applications that need to inspect cloud-key placement.
func (*Module) ObjectAttributes() []uint {
	return []uint{AttributeAlgorithm, AttributeProtectionLevel, AttributeCryptoKeyBackend}
}
