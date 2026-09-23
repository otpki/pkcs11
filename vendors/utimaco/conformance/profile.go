package conformance

import (
	"os"
	"strconv"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	base "github.com/otpki/pkcs11/conformance"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/utimaco"
)

// Profile returns the conformance suite for the simulator flavor selected by
// UTIMACO_PROFILE ("gp" or "qp"). Both run inside the licensed fixture
// containers; they are not runnable without the Utimaco runtime.
func Profile() base.Profile {
	if strings.EqualFold(os.Getenv("UTIMACO_PROFILE"), "qp") {
		return quantumProtectProfile()
	}
	return gpProfile()
}

// gpProfile covers the classical PKCS #11 surface of the SecurityServer
// firmware. The simulator implements the documented 6.x mechanism set; less
// common operations stay optional so firmware gaps surface as skips.
func gpProfile() base.Profile {
	cases := base.HardwareMatrix(
		base.Case{Name: "random", Kind: "random", Requirement: base.Required},
		base.Case{Name: "sha256-digest", Kind: "digest", Requirement: base.Required},
		base.Case{Name: "object-lifecycle", Kind: "object-lifecycle", Requirement: base.Required},
		base.Case{Name: "rsa-3072-generate", Kind: "generate", Requirement: base.Required, Algorithm: pkcs11.AlgorithmRSA, RSABits: 3072},
		base.Case{Name: "rsa-pss-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmRSA, Variant: "pss", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "rsa-pkcs1-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmRSA, Variant: "pkcs1v15", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "rsa-oaep-sha256", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.AlgorithmRSA, Variant: "oaep", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "ecdsa-p256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmECDSAP256},
		base.Case{Name: "ecdsa-p384", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmECDSAP384},
		base.Case{Name: "aes-256-cbc", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.AlgorithmAES256, Variant: "cbc"},
		base.Case{Name: "aes-128-gcm", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.AlgorithmAES128, Variant: "gcm"},
		base.Case{Name: "hmac-sha256", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.AlgorithmHMACSHA256},
		base.Case{Name: "hmac-sha512", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.AlgorithmHMACSHA512},
		base.Case{Name: "aes-key-wrap-pad", Kind: "wrap", Requirement: base.Required},
		base.Case{Name: "ecdh-p256", Kind: "derive-ecdh", Requirement: base.Required, Algorithm: pkcs11.AlgorithmECDSAP256},
		base.Case{Name: "import-aes-256", Kind: "import-secret", Requirement: base.Required, Algorithm: pkcs11.AlgorithmAES256},
		// The simulator firmware accepts a corrupted Ed448 signature at verify
		// time, so the shared case cannot pass; keep it documented but off.
		base.Case{Name: "ed448", Kind: "sign", Requirement: base.Disabled, Algorithm: pkcs11.AlgorithmEd448,
			Notes: "gp simulator returns CKR_OK when verifying a corrupted Ed448 signature"},
		emulatedConcurrentRandom(base.Required),
	)
	promote(cases,
		"rsa-pss-sha384", "rsa-pkcs1-sha384", "rsa-oaep-sha1",
		"ecdsa-p521", "ed25519", "ecdh-p384",
		"aes-128-cbc", "aes-192-cbc", "aes-256-ctr", "aes-256-gcm",
		"hmac-sha384",
		"x509-certificate-object",
	)
	return base.Profile{
		Module:   os.Getenv("PKCS11_MODULE"),
		Token:    tokenProfile(),
		Login:    base.LoginProfile{Mode: pkcs11.LoginLazy, Role: pkcs11.UserRoleUser, PINEnv: "PKCS11_PIN"},
		Sessions: base.SessionProfile{Max: 8, IdleTimeout: 2 * time.Minute},
		Expected: base.ExpectedProfile{Adapter: utimaco.ID},
		Suite:    base.SuiteProfile{Timeout: 25 * time.Minute, CaseTimeout: 3 * time.Minute, Cleanup: true, Prefix: "otpki-uti", Concurrency: 4, Iterations: 10},
		Cases:    cases,
	}
}

// quantumProtectProfile covers the QuantumProtect simulator: the proprietary
// ML-DSA/ML-KEM VDM mechanisms plus a classical sanity subset. HSS/LMS/XMSS
// stay optional until their provider tree parameters are exercised live.
func quantumProtectProfile() base.Profile {
	cases := base.HardwareMatrix(
		base.Case{Name: "random", Kind: "random", Requirement: base.Required},
		base.Case{Name: "sha256-digest", Kind: "digest", Requirement: base.Required},
		base.Case{Name: "ecdsa-p256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmECDSAP256},
		base.Case{Name: "rsa-pss-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmRSA, Variant: "pss", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "ml-dsa-44-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLDSA44, Variant: "direct"},
		base.Case{Name: "ml-dsa-65-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLDSA65, Variant: "direct"},
		base.Case{Name: "ml-dsa-87-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLDSA87, Variant: "direct"},
		// QuantumProtect will not derive a secret less protected than its base
		// key, and the kem cases compare exported secret values, so the ML-KEM
		// private keys must be generated non-sensitive and extractable.
		base.Case{Name: "ml-kem-512", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLKEM512, PrivateAttributes: kemExportablePrivateKey()},
		base.Case{Name: "ml-kem-768", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLKEM768, PrivateAttributes: kemExportablePrivateKey()},
		base.Case{Name: "ml-kem-1024", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.AlgorithmMLKEM1024, PrivateAttributes: kemExportablePrivateKey()},
		base.Case{Name: "lms", Kind: "sign", Requirement: base.Optional, Algorithm: pkcs11.AlgorithmLMS,
			HSS: &base.HSSProfile{Levels: 1, LMSTypes: []base.NumericID{6}, LMOTSTypes: []base.NumericID{3}}},
		base.Case{Name: "hss", Kind: "sign", Requirement: base.Optional, Algorithm: pkcs11.AlgorithmHSS,
			HSS: &base.HSSProfile{Levels: 2, LMSTypes: []base.NumericID{6, 6}, LMOTSTypes: []base.NumericID{3, 3}}},
		emulatedConcurrentRandom(base.Required),
		// Same Ed448 verify quirk as the GP firmware: a corrupted signature is
		// accepted, so the shared negative check cannot pass on this simulator.
		base.Case{Name: "ed448", Kind: "sign", Requirement: base.Disabled, Algorithm: pkcs11.AlgorithmEd448,
			Notes: "quantumprotect simulator returns CKR_OK when verifying a corrupted Ed448 signature"},
	)
	promote(cases,
		"object-lifecycle",
		"ml-dsa-44-prehash", "ml-dsa-65-prehash", "ml-dsa-87-prehash",
		"ml-dsa-44-external-mu", "ml-dsa-65-external-mu", "ml-dsa-87-external-mu",
		"ecdsa-p384", "ed25519", "aes-256-cbc", "hmac-sha256",
	)
	return base.Profile{
		Module:   os.Getenv("PKCS11_MODULE"),
		Token:    tokenProfile(),
		Login:    base.LoginProfile{Mode: pkcs11.LoginLazy, Role: pkcs11.UserRoleUser, PINEnv: "PKCS11_PIN"},
		Sessions: base.SessionProfile{Max: 8, IdleTimeout: 2 * time.Minute},
		Expected: base.ExpectedProfile{Adapter: utimaco.ID},
		Suite:    base.SuiteProfile{Timeout: 40 * time.Minute, CaseTimeout: 5 * time.Minute, Cleanup: true, Prefix: "otpki-utiqp", Concurrency: 4, Iterations: 10},
		Cases:    cases,
	}
}

// tokenProfile selects the token by label, falling back to a numeric slot ID
// for pre-configured simulator slots whose label is unknown.
func tokenProfile() base.TokenProfile {
	profile := base.TokenProfile{Label: os.Getenv("PKCS11_TOKEN_LABEL")}
	if raw := strings.TrimSpace(os.Getenv("PKCS11_SLOT_ID")); raw != "" {
		if slot, err := strconv.ParseUint(raw, 10, 64); err == nil {
			profile.SlotID = &slot
		}
	}
	return profile
}

// emulatedConcurrentRandom lowers the matrix's concurrency load: under
// qemu-i386 the firmware serializes RNG requests and the matrix default
// (8 workers x 20 iterations) exceeds the case timeout.
func emulatedConcurrentRandom(requirement base.Requirement) base.Case {
	return base.Case{Name: "concurrent-random", Kind: "concurrency", Requirement: requirement, Concurrency: 2, Iterations: 2}
}

// kemExportablePrivateKey relaxes the generated ML-KEM private key so a
// decapsulation can return an exportable shared secret. QuantumProtect treats
// the C_DeriveKey base key's protection as the ceiling for the derived object,
// and the kem cases verify the round trip by reading CKA_VALUE.
func kemExportablePrivateKey() []*raw.Attribute {
	return []*raw.Attribute{
		raw.NewAttribute(raw.CKA_SENSITIVE, false),
		raw.NewAttribute(raw.CKA_EXTRACTABLE, true),
	}
}

func promote(cases []base.Case, names ...string) {
	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		selected[name] = struct{}{}
	}
	for index := range cases {
		if _, ok := selected[cases[index].Name]; ok {
			cases[index].Requirement = base.Required
		}
	}
}
