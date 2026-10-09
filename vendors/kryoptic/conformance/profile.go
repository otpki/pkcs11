package conformance

import (
	"os"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	base "github.com/otpki/pkcs11/conformance"
)

// Profile returns the Kryoptic PKCS #11 3.2 and PQC suite.
func Profile() base.Profile {
	return base.Profile{
		Module:   os.Getenv("PKCS11_MODULE"),
		Token:    base.TokenProfile{Label: os.Getenv("PKCS11_TOKEN_LABEL")},
		Login:    base.LoginProfile{Mode: pkcs11.LoginLazy, Role: pkcs11.UserRoleUser, PINEnv: "PKCS11_PIN"},
		Sessions: base.SessionProfile{Max: 16, IdleTimeout: 2 * time.Minute},
		Expected: base.ExpectedProfile{Adapter: "kryoptic", MinimumInterface: "3.2"},
		Suite:    base.SuiteProfile{Timeout: 90 * time.Minute, CaseTimeout: 10 * time.Minute, Cleanup: true, Prefix: "otpki-kryoptic", Concurrency: 8, Iterations: 20},
		Cases: base.HardwareMatrix(
			base.Case{Name: "random", Kind: "random", Requirement: base.Required},
			base.Case{Name: "sha256-digest", Kind: "digest", Requirement: base.Required},
			base.Case{Name: "concurrent-random", Kind: "concurrency", Requirement: base.Required, Concurrency: 12, Iterations: 30},
			base.Case{Name: "rsa-pss-sha256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 3072},
			base.Case{Name: "ecdsa-p256", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
			base.Case{Name: "ed25519", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ed25519")},
			base.Case{Name: "aes-256-gcm", Kind: "encrypt", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-256"), Variant: "gcm"},
			base.Case{Name: "hmac-sha256", Kind: "hmac", Requirement: base.Required, Algorithm: pkcs11.Algorithm("hmac-sha256")},
			base.Case{Name: "ecdh-p256", Kind: "derive-ecdh", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
			base.Case{Name: "import-aes-256", Kind: "import-secret", Requirement: base.Required, Algorithm: pkcs11.Algorithm("aes-256")},
			base.Case{Name: "ml-dsa-44-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Variant: "direct", MessageBytes: 64},
			base.Case{Name: "ml-dsa-44-prehash", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Variant: "prehash", Hash: "sha512", MessageBytes: 64},
			base.Case{Name: "ml-dsa-65-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "direct", MessageBytes: 64},
			base.Case{Name: "ml-dsa-65-prehash", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "prehash", Hash: "sha512", MessageBytes: 64},
			base.Case{Name: "ml-dsa-87-direct", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-87"), Variant: "direct", MessageBytes: 64},
			base.Case{Name: "ml-dsa-87-prehash", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-dsa-87"), Variant: "prehash", Hash: "sha512", MessageBytes: 64},
			base.Case{Name: "ml-kem-512", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-kem-512")},
			base.Case{Name: "ml-kem-768", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-kem-768")},
			base.Case{Name: "ml-kem-1024", Kind: "kem", Requirement: base.Required, Algorithm: pkcs11.Algorithm("ml-kem-1024")},
			base.Case{Name: "slh-dsa-sha2-128s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-128s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-sha2-128f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-128f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-sha2-192s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-192s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-sha2-192f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-192f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-sha2-256s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-256s", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256s"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-sha2-256f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "slh-dsa-shake-256f", Kind: "sign", Requirement: base.Required, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256f"), Variant: "direct", MessageBytes: 32},
			base.Case{Name: "ml-dsa-65-external-mu", Kind: "sign", Requirement: base.Optional, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "external-mu", Notes: "Requires a vendor external-mu alias; external mu is not a standard PKCS #11 3.2 mechanism."},
			base.Case{Name: "pub-key-from-priv-rsa", Kind: "pub-key-from-priv", Requirement: base.Required, Algorithm: pkcs11.Algorithm("rsa"), Variant: "rsa", RSABits: 2048},
			base.Case{Name: "pub-key-from-priv-ecdsa", Kind: "pub-key-from-priv", Requirement: base.Disabled, Algorithm: pkcs11.Algorithm("ecdsa-p256"), Notes: "Known gap: kryoptic implements CKM_PUB_KEY_FROM_PRIV_KEY only for RSA, ML-KEM, ML-DSA, and SLH-DSA keys; EC private keys have no public-object factory path."},
			base.Case{Name: "derive-aes-cbc-encrypt", Kind: "derive-encrypt", Requirement: base.Disabled, Variant: "aes-cbc", Notes: "Known gap: kryoptic stores the CK_AES_CBC_ENCRYPT_DATA_PARAMS IV as a borrowed slice of the stack-resident parameter copy, so C_DeriveKey reads a dangling IV; the derived value is unpredictable."},
		),
	}
}
