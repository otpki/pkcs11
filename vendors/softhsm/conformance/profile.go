package conformance

import (
	"os"
	"slices"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	base "github.com/otpki/pkcs11/conformance"
)

// Profile returns the SoftHSM 2 integration suite as ordinary Go data.
func Profile() base.Profile {
	cases := base.HardwareMatrix(
		base.Case{Name: "random", Kind: "random", Requirement: base.Required},
		base.Case{Name: "sha256-digest", Kind: "digest", Requirement: base.Required},
		base.Case{Name: "concurrent-random", Kind: "concurrency", Requirement: base.Required, Concurrency: 12, Iterations: 30},
		base.Case{Name: "object-lifecycle", Kind: "object-lifecycle", Requirement: base.Required},
		base.Case{Name: "rsa-3072-generate", Kind: "generate", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), RSABits: 3072},
		base.Case{Name: "rsa-pss-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "rsa-pkcs1-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "rsa-oaep-sha1", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha1", RSABits: 3072},
		base.Case{Name: "rsa-oaep-sha256", Kind: "encrypt", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha256", RSABits: 3072},
		base.Case{Name: "ecdsa-p256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
		base.Case{Name: "ecdsa-p384", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p384")},
		base.Case{Name: "ecdsa-p521", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p521")},
		base.Case{Name: "aes-128-gcm", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "gcm"},
		base.Case{Name: "aes-192-cbc", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-192"), Variant: "cbc"},
		base.Case{Name: "aes-256-ctr", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-256"), Variant: "ctr"},
		base.Case{Name: "hmac-sha256", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.Algorithm("hmac-sha256")},
		base.Case{Name: "hmac-sha384", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.Algorithm("hmac-sha384")},
		base.Case{Name: "hmac-sha512", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.Algorithm("hmac-sha512")},
		base.Case{Name: "aes-key-wrap-pad", Kind: "wrap", Requirement: base.Required},
		base.Case{Name: "ecdh-p256", Kind: "derive-ecdh", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
		base.Case{Name: "import-aes-256", Kind: "import-secret", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-256")},
		base.Case{Name: "message-rsa-pss-sha256", Kind: "message-sign", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 2048},
		base.Case{Name: "signature-first-rsa-pss-sha256", Kind: "signature-first-verify", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 2048},
		base.Case{Name: "authenticated-aes-key-wrap-pad", Kind: "authenticated-wrap", Requirement: base.Optional},
		base.Case{Name: "session-validation-flags", Kind: "session-validation", Requirement: base.Optional},
		base.Case{Name: "rsa-oaep-sha384", Kind: "encrypt", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha384", RSABits: 3072},
		base.Case{Name: "rsa-oaep-sha512", Kind: "encrypt", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha512", RSABits: 3072},
	)
	promote(cases,
		"runtime", "sessions", "x509-certificate-object",
		"import-aes-128", "import-aes-192",
		"rsa-pss-sha384", "rsa-pkcs1-sha384", "rsa-pss-sha512", "rsa-pkcs1-sha512", "rsa-pkcs1-encrypt",
		"rsa-pss-sha3-224", "rsa-pkcs1-sha3-224", "rsa-pss-sha3-256", "rsa-pkcs1-sha3-256",
		"rsa-pss-sha3-384", "rsa-pkcs1-sha3-384", "rsa-pss-sha3-512", "rsa-pkcs1-sha3-512",
		"ed25519", "ecdh-p384", "ecdh-p521",
		"aes-128-cbc", "aes-128-ctr", "aes-192-gcm", "aes-192-ctr", "aes-256-gcm", "aes-256-cbc",
		"ml-dsa-44-direct", "ml-dsa-65-direct", "ml-dsa-87-direct",
		"ml-kem-512", "ml-kem-768", "ml-kem-1024",
	)
	annotate(cases,
		"known gap: SoftHSM advertises no message-mode flags on CKM_RSA_PKCS_PSS, so C_SignMessage is unsupported",
		"message-rsa-pss-sha256", "message-rsa-pss-sha3-256",
	)
	annotate(cases,
		"known gap: SoftHSM does not implement C_VerifySignatureInit/C_VerifySignature",
		"signature-first-rsa-pss-sha256", "signature-first-rsa-pss-sha3-256",
	)
	return base.Profile{
		Module:   os.Getenv("PKCS11_MODULE"),
		Token:    base.TokenProfile{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Login:    base.LoginProfile{Mode: pkcs11.LoginLazy, Role: pkcs11.UserRoleUser, PINEnv: "PKCS11_PIN"},
		Sessions: base.SessionProfile{Max: 16, IdleTimeout: 2 * time.Minute},
		Expected: base.ExpectedProfile{Adapter: "softhsm2", MinimumInterface: "3.2"},
		Suite:    base.SuiteProfile{Timeout: 20 * time.Minute, CaseTimeout: 3 * time.Minute, Cleanup: true, Prefix: "otpki-soft", Concurrency: 8, Iterations: 20},
		Cases:    cases,
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

// annotate records provider gap notes on named cases without changing their
// requirement, keeping the documented limitation beside the case it affects.
func annotate(cases []base.Case, note string, names ...string) {
	for index := range cases {
		if cases[index].Notes == "" && slices.Contains(names, cases[index].Name) {
			cases[index].Notes = note
		}
	}
}
