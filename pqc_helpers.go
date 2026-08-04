package pkcs11

import (
	"crypto"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// HedgeMode controls the PKCS #11 3.2 randomized-signing policy for ML-DSA
// and SLH-DSA. Providers may reject a mode they do not implement.
type HedgeMode uint

const (
	// HedgePreferred permits randomized signing and lets the provider fall back
	// to deterministic signing when fresh randomness is unavailable.
	HedgePreferred HedgeMode = HedgeMode(raw.CKH_HEDGE_PREFERRED)
	// HedgeRequired requires randomized signing.
	HedgeRequired HedgeMode = HedgeMode(raw.CKH_HEDGE_REQUIRED)
	// DeterministicOnly disables hedged signing.
	DeterministicOnly HedgeMode = HedgeMode(raw.CKH_DETERMINISTIC_REQUIRED)
)

// StandardPQCSignatures is the set of signature algorithms standardized by
// PKCS #11 3.2 and exposed directly by this driver. Treat the slice as read-only;
// use append([]Algorithm(nil), StandardPQCSignatures...) before modifying it.
var StandardPQCSignatures = []Algorithm{
	AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87,
	AlgorithmSLHDSASHA2128S, AlgorithmSLHDSASHAKE128S, AlgorithmSLHDSASHA2128F, AlgorithmSLHDSASHAKE128F,
	AlgorithmSLHDSASHA2192S, AlgorithmSLHDSASHAKE192S, AlgorithmSLHDSASHA2192F, AlgorithmSLHDSASHAKE192F,
	AlgorithmSLHDSASHA2256S, AlgorithmSLHDSASHAKE256S, AlgorithmSLHDSASHA2256F, AlgorithmSLHDSASHAKE256F,
	AlgorithmHSS, AlgorithmXMSS, AlgorithmXMSSMT,
}

// StandardPQCKEMs is the set of KEM algorithms standardized by PKCS #11 3.2.
// Treat the slice as read-only.
var StandardPQCKEMs = []Algorithm{AlgorithmMLKEM512, AlgorithmMLKEM768, AlgorithmMLKEM1024}

// PQCDirect constructs options for direct-message ML-DSA or SLH-DSA signing.
func PQCDirect(context []byte, hedge HedgeMode) SignatureOptions {
	return SignatureOptions{Context: append([]byte(nil), context...), Hedge: hedge}
}

// PQCPrehash selects the PKCS #11 3.2 hash-signing route. Sign receives the
// digest and hash identifies its algorithm.
func PQCPrehash(hash crypto.Hash, context []byte, hedge HedgeMode) SignatureOptions {
	return SignatureOptions{Hash: hash, Prehashed: true, Context: append([]byte(nil), context...), Hedge: hedge}
}

// PQCExternalMu selects vendor external-mu ML-DSA routing. The 64-byte mu is
// the data passed to Sign; mechanismParameter is normally nil. This is a vendor
// extension rather than a portable PKCS #11 3.2 operation.
func PQCExternalMu(mechanismParameter any) SignatureOptions {
	return SignatureOptions{ExternalMu: true, MechanismParameter: mechanismParameter}
}

// PQCMechanismOverride selects an explicit standard or vendor mechanism while
// retaining managed sessions, retries, hooks and recovery.
func PQCMechanismOverride(mechanism uint, parameter any) SignatureOptions {
	return SignatureOptions{MechanismOverride: &mechanism, MechanismParameter: parameter}
}

// IsPQCSignature reports whether algorithm is a supported post-quantum signature family.
func IsPQCSignature(algorithm Algorithm) bool {
	if slices.Contains(StandardPQCSignatures, algorithm) {
		return true
	}
	switch algorithm {
	case AlgorithmDilithium2, AlgorithmDilithium3, AlgorithmDilithium5, AlgorithmFalcon512, AlgorithmFalcon1024, AlgorithmSPHINCSPlus, AlgorithmComposite, AlgorithmHybrid:
		return true
	default:
		return false
	}
}

// IsPQCKEM reports whether algorithm is a supported post-quantum KEM family.
func IsPQCKEM(algorithm Algorithm) bool {
	switch algorithm {
	case AlgorithmMLKEM512, AlgorithmMLKEM768, AlgorithmMLKEM1024, AlgorithmKyber512, AlgorithmKyber768, AlgorithmKyber1024:
		return true
	default:
		return false
	}
}
