package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// rsaDigestInfoPrefixes contains DER AlgorithmIdentifier+OCTET STRING prefixes
// for EMSA-PKCS1-v1_5. CKM_RSA_PKCS expects this DigestInfo payload when the
// application, rather than the token, performed the hash.
var rsaDigestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// prepareSignatureInput converts Go's crypto.Signer convention into the input
// expected by the selected raw PKCS #11 mechanism. CKM_RSA_PKCS signs an
// already encoded EMSA-PKCS1-v1_5 payload, so a prehashed input needs its ASN.1
// DigestInfo prefix. CKM_RSA_PKCS_PSS and raw ECDSA consume the digest itself.
func prepareSignatureInput(intent Intent, input []byte) ([]byte, error) {
	if !intent.Prehashed {
		return input, nil
	}
	if intent.Hash == 0 {
		return nil, fmt.Errorf("pkcs11: prehashed %s input requires an explicit hash", intent.Algorithm)
	}
	if len(input) != intent.Hash.Size() {
		return nil, fmt.Errorf("pkcs11: %s digest is %d bytes; %s requires %d", intent.Algorithm, len(input), intent.Hash, intent.Hash.Size())
	}
	if intent.Algorithm != AlgorithmRSA {
		return input, nil
	}
	padding := intent.RSAPadding
	if padding == "" {
		padding = RSAPaddingPSS
	}
	if padding != RSAPaddingPKCS1v15 {
		return input, nil
	}
	prefix, ok := rsaDigestInfoPrefixes[intent.Hash]
	if !ok {
		return nil, fmt.Errorf("pkcs11: RSA PKCS#1 v1.5 does not support hash %v", intent.Hash)
	}
	encoded := make([]byte, 0, len(prefix)+len(input))
	encoded = append(encoded, prefix...)
	encoded = append(encoded, input...)
	return encoded, nil
}

// pssSaltLength translates crypto/rsa sentinel values into the explicit byte
// count required by CK_RSA_PKCS_PSS_PARAMS. PSSSaltLengthAuto uses the largest
// salt permitted by the encoded-message width, matching Go's signing behavior.
func pssSaltLength(publicKey crypto.PublicKey, hash crypto.Hash, requested int) (int, error) {
	if hash == 0 {
		return 0, fmt.Errorf("pkcs11: RSA-PSS requires a hash")
	}
	switch requested {
	case rsa.PSSSaltLengthEqualsHash:
		return hash.Size(), nil
	case rsa.PSSSaltLengthAuto:
		public, ok := publicKey.(*rsa.PublicKey)
		if !ok || public == nil || public.N == nil {
			return 0, fmt.Errorf("pkcs11: RSA-PSS automatic salt length requires an RSA public key")
		}
		// RFC 8017 uses emBits = modBits-1 for RSASSA-PSS, then rounds up to the
		// encoded-message length in octets.
		emLen := ((public.N.BitLen() - 1) + 7) / 8
		maximum := emLen - hash.Size() - 2
		if maximum < 0 {
			return 0, fmt.Errorf("pkcs11: RSA key is too small for %s PSS", hash)
		}
		return maximum, nil
	default:
		if requested < 0 {
			return 0, fmt.Errorf("pkcs11: invalid RSA-PSS salt length %d", requested)
		}
		return requested, nil
	}
}
