package conformance

import (
	"slices"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
)

// HardwareMatrix returns an independent copy of the complete portable case matrix.
// Overrides replace cases with the same name; new names are appended.
func HardwareMatrix(overrides ...Case) []Case {
	cases := slices.Clone(hardwareMatrix)
	for index := range cases {
		cases[index] = cloneMatrixCase(cases[index])
	}
	indexes := make(map[string]int, len(cases))
	for index, testCase := range cases {
		indexes[testCase.Name] = index
	}
	for _, override := range overrides {
		if index, ok := indexes[override.Name]; ok {
			cases[index] = cloneMatrixCase(override)
			continue
		}
		indexes[override.Name] = len(cases)
		cases = append(cases, cloneMatrixCase(override))
	}
	return cases
}

func cloneMatrixCase(testCase Case) Case {
	if testCase.HSS != nil {
		hss := *testCase.HSS
		hss.LMSTypes = slices.Clone(hss.LMSTypes)
		hss.LMOTSTypes = slices.Clone(hss.LMOTSTypes)
		testCase.HSS = &hss
	}
	if testCase.ExpectRecovery != nil {
		value := *testCase.ExpectRecovery
		testCase.ExpectRecovery = &value
	}
	if testCase.Verify != nil {
		value := *testCase.Verify
		testCase.Verify = &value
	}
	return testCase
}

var hardwareMatrix = []Case{
	{Name: "runtime", Kind: "runtime", Requirement: Required},
	{Name: "random", Kind: "random", Requirement: Optional},
	{Name: "sessions", Kind: "session", Requirement: Required},
	{Name: "sha256-digest", Kind: "digest", Requirement: Optional},
	{Name: "concurrent-random", Kind: "concurrency", Requirement: Optional, Concurrency: 8, Iterations: 20},
	{Name: "object-lifecycle", Kind: "object-lifecycle", Requirement: Optional},
	{Name: "import-aes-128", Kind: "import-secret", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128")},
	{Name: "import-aes-192", Kind: "import-secret", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-192")},
	{Name: "import-aes-256", Kind: "import-secret", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-256")},
	{Name: "rsa-pss-sha256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 3072},
	{Name: "rsa-pkcs1-sha256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha256", RSABits: 3072},
	{Name: "rsa-oaep-sha256", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha256", RSABits: 3072},
	{Name: "rsa-pss-sha384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha384", RSABits: 3072},
	{Name: "rsa-pkcs1-sha384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha384", RSABits: 3072},
	{Name: "rsa-oaep-sha384", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha384", RSABits: 3072},
	{Name: "rsa-pss-sha512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha512", RSABits: 3072},
	{Name: "rsa-pkcs1-sha512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha512", RSABits: 3072},
	{Name: "rsa-oaep-sha512", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "oaep", Hash: "sha512", RSABits: 3072},
	{Name: "rsa-pkcs1-encrypt", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha256", RSABits: 3072},
	{Name: "rsa-pss-sha3-224", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-224", RSABits: 3072},
	{Name: "rsa-pkcs1-sha3-224", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha3-224", RSABits: 3072},
	{Name: "rsa-pss-sha3-256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-256", RSABits: 3072},
	{Name: "rsa-pkcs1-sha3-256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha3-256", RSABits: 3072},
	{Name: "rsa-pss-sha3-384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-384", RSABits: 3072},
	{Name: "rsa-pkcs1-sha3-384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha3-384", RSABits: 3072},
	{Name: "rsa-pss-sha3-512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-512", RSABits: 3072},
	{Name: "rsa-pkcs1-sha3-512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pkcs1v15", Hash: "sha3-512", RSABits: 3072},
	{Name: "ecdsa-p256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
	{Name: "ecdsa-p384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p384")},
	{Name: "ecdsa-p521", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p521")},
	{Name: "ed25519", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ed25519")},
	{Name: "ed448", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ed448")},
	{Name: "ecdh-p256", Kind: "derive-ecdh", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
	{Name: "ecdh-p384", Kind: "derive-ecdh", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p384")},
	{Name: "ecdh-p521", Kind: "derive-ecdh", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p521")},
	{Name: "aes-128-gcm", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "gcm"},
	{Name: "aes-128-cbc", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "cbc"},
	{Name: "aes-128-ctr", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "ctr"},
	{Name: "aes-192-gcm", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-192"), Variant: "gcm"},
	{Name: "aes-192-cbc", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-192"), Variant: "cbc"},
	{Name: "aes-192-ctr", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-192"), Variant: "ctr"},
	{Name: "aes-256-gcm", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-256"), Variant: "gcm"},
	{Name: "aes-256-cbc", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-256"), Variant: "cbc"},
	{Name: "aes-256-ctr", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-256"), Variant: "ctr"},
	{Name: "chacha20", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("chacha20"), Variant: "chacha20"},
	{Name: "chacha20-poly1305", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("chacha20"), Variant: "chacha20-poly1305"},
	{Name: "hmac-sha256", Kind: "hmac", Requirement: Optional, Algorithm: pkcs11.Algorithm("hmac-sha256")},
	{Name: "hmac-sha384", Kind: "hmac", Requirement: Optional, Algorithm: pkcs11.Algorithm("hmac-sha384")},
	{Name: "hmac-sha512", Kind: "hmac", Requirement: Optional, Algorithm: pkcs11.Algorithm("hmac-sha512")},
	{Name: "aes-key-wrap-pad", Kind: "wrap", Requirement: Optional},
	{Name: "aes-key-wrap-kwp", Kind: "wrap", Requirement: Optional, Variant: "kwp"},
	{Name: "aes-key-wrap-pkcs7", Kind: "wrap", Requirement: Optional, Variant: "pkcs7"},
	{Name: "derive-sha256", Kind: "derive-hash", Requirement: Optional, Variant: "sha256"},
	{Name: "derive-sha384", Kind: "derive-hash", Requirement: Optional, Variant: "sha384"},
	{Name: "derive-sha512", Kind: "derive-hash", Requirement: Optional, Variant: "sha512"},
	{Name: "derive-sha3-256", Kind: "derive-hash", Requirement: Optional, Variant: "sha3-256"},
	{Name: "derive-hkdf-sha256", Kind: "derive-hkdf", Requirement: Optional, Hash: "sha256"},
	{Name: "derive-ike-prf", Kind: "derive-ike", Requirement: Optional},
	{Name: "trust-object", Kind: "trust-object", Requirement: Optional},
	{Name: "validation-object", Kind: "validation-object", Requirement: Optional},
	{Name: "message-aead-chacha20-poly1305", Kind: "message-aead", Requirement: Optional, Variant: "chacha20-poly1305"},
	{Name: "message-aead-aes-gcm", Kind: "message-aead", Requirement: Optional, Variant: "gcm"},
	{Name: "authenticated-aes-key-wrap-pad", Kind: "authenticated-wrap", Requirement: Optional},
	{Name: "x509-certificate-object", Kind: "certificate", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), RSABits: 2048},
	{Name: "message-rsa-pss-sha256", Kind: "message-sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 2048},
	{Name: "signature-first-rsa-pss-sha256", Kind: "signature-first-verify", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 2048},
	{Name: "message-rsa-pss-sha3-256", Kind: "message-sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-256", RSABits: 2048},
	{Name: "signature-first-rsa-pss-sha3-256", Kind: "signature-first-verify", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha3-256", RSABits: 2048},
	{Name: "session-validation-flags", Kind: "session-validation", Requirement: Optional},
	{Name: "md5-digest", Kind: "digest", Requirement: Optional, Hash: "md5"},
	{Name: "sha512-224-digest", Kind: "digest", Requirement: Optional, Hash: "sha512-224"},
	{Name: "sha512-256-digest", Kind: "digest", Requirement: Optional, Hash: "sha512-256"},
	{Name: "ecdsa-p256-sha3-224", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p256"), Variant: "token-hash", Hash: "sha3-224"},
	{Name: "ecdsa-p256-sha3-256", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p256"), Variant: "token-hash", Hash: "sha3-256"},
	{Name: "ecdsa-p384-sha3-384", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p384"), Variant: "token-hash", Hash: "sha3-384"},
	{Name: "ecdsa-p521-sha3-512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p521"), Variant: "token-hash", Hash: "sha3-512"},
	{Name: "dsa-sha256", Kind: "dsa", Requirement: Optional, Algorithm: pkcs11.Algorithm("dsa"), Hash: "sha256"},
	{Name: "dsa-sha256-token-hash", Kind: "dsa", Requirement: Optional, Algorithm: pkcs11.Algorithm("dsa"), Variant: "token-hash", Hash: "sha256"},
	{Name: "dsa-parameter-gen", Kind: "parameter-gen", Requirement: Optional, Algorithm: pkcs11.Algorithm("dsa"), Variant: "dsa"},
	{Name: "dh-parameter-gen", Kind: "parameter-gen", Requirement: Optional, Algorithm: pkcs11.Algorithm("dh"), Variant: "dh"},
	{Name: "dh-ffdhe2048", Kind: "derive-dh", Requirement: Optional, Algorithm: pkcs11.Algorithm("dh")},
	{Name: "x25519", Kind: "derive-montgomery", Requirement: Optional, Algorithm: pkcs11.Algorithm("x25519")},
	{Name: "x448", Kind: "derive-montgomery", Requirement: Optional, Algorithm: pkcs11.Algorithm("x448")},
	{Name: "aes-cmac", Kind: "mac", Requirement: Optional, Variant: "aes-cmac"},
	{Name: "aes-cmac-general", Kind: "mac", Requirement: Optional, Variant: "aes-cmac-general"},
	{Name: "hmac-sha256-general", Kind: "mac", Requirement: Optional, Variant: "hmac-sha256-general"},
	{Name: "hmac-sha384-general", Kind: "mac", Requirement: Optional, Variant: "hmac-sha384-general"},
	{Name: "hmac-sha512-general", Kind: "mac", Requirement: Optional, Variant: "hmac-sha512-general"},
	{Name: "aes-128-ccm", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "ccm"},
	{Name: "aes-128-cts", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "cts"},
	{Name: "aes-128-ofb", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "ofb"},
	{Name: "aes-128-cfb128", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "cfb128"},
	{Name: "aes-128-cfb8", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "cfb8"},
	{Name: "aes-128-cfb1", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "cfb1"},
	{Name: "aes-128-ecb", Kind: "encrypt", Requirement: Optional, Algorithm: pkcs11.Algorithm("aes-128"), Variant: "ecb"},
	{Name: "des-cbc", Kind: "des", Requirement: Optional, Variant: "des-cbc"},
	{Name: "des3-cbc", Kind: "des", Requirement: Optional, Variant: "des3-cbc"},
	{Name: "derive-aes-cbc-encrypt", Kind: "derive-encrypt", Requirement: Optional, Variant: "aes-cbc"},
	{Name: "derive-aes-ecb-encrypt", Kind: "derive-encrypt", Requirement: Optional, Variant: "aes-ecb"},
	{Name: "derive-concatenate-base-data", Kind: "derive-concatenate", Requirement: Optional, Variant: "base-data"},
	{Name: "derive-concatenate-data-base", Kind: "derive-concatenate", Requirement: Optional, Variant: "data-base"},
	{Name: "derive-concatenate-base-key", Kind: "derive-concatenate", Requirement: Optional, Variant: "base-key"},
	{Name: "derive-xor-base-data", Kind: "derive-concatenate", Requirement: Optional, Variant: "xor"},
	{Name: "derive-extract", Kind: "derive-extract", Requirement: Optional},
	{Name: "rsa-aes-key-wrap", Kind: "rsa-aes-wrap", Requirement: Optional},
	{Name: "derive-sp800-108-counter", Kind: "derive-sp800", Requirement: Optional, Variant: "counter"},
	{Name: "derive-sp800-108-feedback", Kind: "derive-sp800", Requirement: Optional, Variant: "feedback"},
	{Name: "derive-tls-kdf", Kind: "derive-tls", Requirement: Optional, Variant: "kdf"},
	{Name: "derive-tls12-kdf", Kind: "derive-tls", Requirement: Optional, Variant: "tls12"},
	{Name: "derive-tls12-master-key", Kind: "derive-tls", Requirement: Optional, Variant: "master"},
	{Name: "derive-tls12-extended-master-key", Kind: "derive-tls", Requirement: Optional, Variant: "extended"},
	{Name: "derive-tls12-key-material", Kind: "derive-tls", Requirement: Optional, Variant: "key-mat"},
	{Name: "tls-mac-client", Kind: "tls-mac", Requirement: Optional},
	{Name: "tls-mac-server", Kind: "tls-mac", Requirement: Optional, Variant: "server"},
	{Name: "hotp", Kind: "hotp", Requirement: Optional},
	{Name: "pbkdf2-sha256", Kind: "pbkdf2", Requirement: Optional},
	{Name: "pub-key-from-priv-ecdsa", Kind: "pub-key-from-priv", Requirement: Optional, Algorithm: pkcs11.Algorithm("ecdsa-p256")},
	{Name: "pub-key-from-priv-rsa", Kind: "pub-key-from-priv", Requirement: Optional, Algorithm: pkcs11.Algorithm("rsa"), Variant: "rsa", RSABits: 2048},
	{Name: "hmac-keygen-sha256", Kind: "hmac-keygen", Requirement: Optional, Variant: "sha256"},
	{Name: "hmac-keygen-sha384", Kind: "hmac-keygen", Requirement: Optional, Variant: "sha384"},
	{Name: "hmac-keygen-sha512", Kind: "hmac-keygen", Requirement: Optional, Variant: "sha512"},
	{Name: "hmac-keygen-sha512-224", Kind: "hmac-keygen", Requirement: Optional, Variant: "sha512-224"},
	{Name: "hmac-keygen-sha512-256", Kind: "hmac-keygen", Requirement: Optional, Variant: "sha512-256"},
	{Name: "derive-sha1", Kind: "derive-hash", Requirement: Optional, Variant: "sha1"},
	{Name: "derive-sha224", Kind: "derive-hash", Requirement: Optional, Variant: "sha224"},
	{Name: "derive-sha512-224", Kind: "derive-hash", Requirement: Optional, Variant: "sha512-224"},
	{Name: "derive-sha512-256", Kind: "derive-hash", Requirement: Optional, Variant: "sha512-256"},
	{Name: "derive-sha3-224", Kind: "derive-hash", Requirement: Optional, Variant: "sha3-224"},
	{Name: "derive-sha3-384", Kind: "derive-hash", Requirement: Optional, Variant: "sha3-384"},
	{Name: "derive-sha3-512", Kind: "derive-hash", Requirement: Optional, Variant: "sha3-512"},
	{Name: "derive-ike1-prf", Kind: "derive-ike1-prf", Requirement: Optional},
	{Name: "derive-ike2-prf-plus", Kind: "derive-ike2-prf-plus", Requirement: Optional},
	{Name: "derive-ike1-extended", Kind: "derive-ike1-extended", Requirement: Optional},
	{Name: "ml-dsa-44-token-prehash-sha256", Kind: "token-prehash", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Hash: "sha256"},
	{Name: "ml-dsa-65-token-prehash-sha512", Kind: "token-prehash", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Hash: "sha512"},
	{Name: "slh-dsa-sha2-128s-token-prehash-sha256", Kind: "token-prehash", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128s"), Hash: "sha256"},
	{Name: "slh-dsa-shake-128f-token-prehash-shake128", Kind: "token-prehash", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128f"), Hash: "shake128"},
	{Name: "profile-object", Kind: "profile-object", Requirement: Optional},
	{Name: "ml-dsa-44-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Variant: "direct"},
	{Name: "ml-dsa-44-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Variant: "prehash", Hash: "sha512"},
	{Name: "ml-dsa-44-external-mu", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-44"), Variant: "external-mu"},
	{Name: "ml-dsa-65-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "direct"},
	{Name: "ml-dsa-65-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "prehash", Hash: "sha512"},
	{Name: "ml-dsa-65-external-mu", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-65"), Variant: "external-mu"},
	{Name: "ml-dsa-87-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-87"), Variant: "direct"},
	{Name: "ml-dsa-87-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-87"), Variant: "prehash", Hash: "sha512"},
	{Name: "ml-dsa-87-external-mu", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-dsa-87"), Variant: "external-mu"},
	{Name: "ml-kem-512", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-kem-512")},
	{Name: "ml-kem-768", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-kem-768")},
	{Name: "ml-kem-1024", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("ml-kem-1024")},
	{Name: "slh-dsa-sha2-128s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128s"), Variant: "direct"},
	{Name: "slh-dsa-sha2-128s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-sha2-128f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128f"), Variant: "direct"},
	{Name: "slh-dsa-sha2-128f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-128f"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-sha2-192s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192s"), Variant: "direct"},
	{Name: "slh-dsa-sha2-192s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-sha2-192f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192f"), Variant: "direct"},
	{Name: "slh-dsa-sha2-192f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-192f"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-sha2-256s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256s"), Variant: "direct"},
	{Name: "slh-dsa-sha2-256s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-sha2-256f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256f"), Variant: "direct"},
	{Name: "slh-dsa-sha2-256f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-sha2-256f"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-128s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128s"), Variant: "direct"},
	{Name: "slh-dsa-shake-128s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-128f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128f"), Variant: "direct"},
	{Name: "slh-dsa-shake-128f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-128f"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-192s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192s"), Variant: "direct"},
	{Name: "slh-dsa-shake-192s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-192f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192f"), Variant: "direct"},
	{Name: "slh-dsa-shake-192f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-192f"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-256s-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256s"), Variant: "direct"},
	{Name: "slh-dsa-shake-256s-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256s"), Variant: "prehash", Hash: "sha512"},
	{Name: "slh-dsa-shake-256f-direct", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256f"), Variant: "direct"},
	{Name: "slh-dsa-shake-256f-prehash", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("slh-dsa-shake-256f"), Variant: "prehash", Hash: "sha512"},
	{Name: "dilithium-2", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("dilithium-2"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "dilithium-3", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("dilithium-3"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "dilithium-5", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("dilithium-5"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "falcon-512", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("falcon-512"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "falcon-1024", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("falcon-1024"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "sphincs-plus", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("sphincs-plus"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "composite", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("composite"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "hybrid", Kind: "sign", Requirement: Optional, Algorithm: pkcs11.Algorithm("hybrid"), Variant: "direct", Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "kyber-512", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("kyber-512"), Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "kyber-768", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("kyber-768"), Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "kyber-1024", Kind: "kem", Requirement: Optional, Algorithm: pkcs11.Algorithm("kyber-1024"), Notes: "Requires a supplied VendorModule whose catalog defines the needed proprietary identifiers."},
	{Name: "lms", Kind: "sign", Requirement: Disabled, Algorithm: pkcs11.Algorithm("lms"), Notes: "Fill in the device-specific LMS/LM-OTS tree configuration before enabling."},
	{Name: "hss", Kind: "sign", Requirement: Disabled, Algorithm: pkcs11.Algorithm("hss"), Notes: "Fill in the device-specific parameter-set or tree configuration before enabling."},
	{Name: "xmss", Kind: "sign", Requirement: Disabled, Algorithm: pkcs11.Algorithm("xmss"), Notes: "Fill in the device-specific parameter-set or tree configuration before enabling."},
	{Name: "xmssmt", Kind: "sign", Requirement: Disabled, Algorithm: pkcs11.Algorithm("xmssmt"), Notes: "Fill in the device-specific parameter-set or tree configuration before enabling."},
	{Name: "idle-session-recovery", Kind: "idle-recovery", Requirement: Disabled, Algorithm: pkcs11.Algorithm("rsa"), Variant: "pss", Hash: "sha256", RSABits: 2048, IdleFor: 20 * time.Minute, Notes: "Enable only in a scheduled hardware job; choose a duration beyond the provider idle timeout."},
}
