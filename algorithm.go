package pkcs11

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// Algorithm identifies a vendor-neutral key or cryptographic algorithm.
// Resolution to standard or proprietary mechanisms happens after token detection.
type Algorithm string

const (
	// AlgorithmRSA selects RSA key generation, signatures, encryption, and decryption.
	AlgorithmRSA Algorithm = "rsa"
	// AlgorithmECDSAP256 selects ECDSA over the NIST P-256 curve.
	AlgorithmECDSAP256 Algorithm = "ecdsa-p256"
	// AlgorithmECDSAP384 selects ECDSA over the NIST P-384 curve.
	AlgorithmECDSAP384 Algorithm = "ecdsa-p384"
	// AlgorithmECDSAP521 selects ECDSA over the NIST P-521 curve.
	AlgorithmECDSAP521 Algorithm = "ecdsa-p521"
	// AlgorithmEd25519 selects Ed25519 or Ed25519ph according to signature options.
	AlgorithmEd25519 Algorithm = "ed25519"
	// AlgorithmEd448 selects Ed448 or Ed448ph according to signature options.
	AlgorithmEd448 Algorithm = "ed448"
	// AlgorithmAES128 selects a 128-bit AES secret key.
	AlgorithmAES128 Algorithm = "aes-128"
	// AlgorithmAES192 selects a 192-bit AES secret key.
	AlgorithmAES192 Algorithm = "aes-192"
	// AlgorithmAES256 selects a 256-bit AES secret key.
	AlgorithmAES256 Algorithm = "aes-256"
	// AlgorithmHMACSHA256 selects an HMAC key intended for SHA-256.
	AlgorithmHMACSHA256 Algorithm = "hmac-sha256"
	// AlgorithmHMACSHA384 selects an HMAC key intended for SHA-384.
	AlgorithmHMACSHA384 Algorithm = "hmac-sha384"
	// AlgorithmHMACSHA512 selects an HMAC key intended for SHA-512.
	AlgorithmHMACSHA512 Algorithm = "hmac-sha512"
	// AlgorithmHSS selects the hierarchical LMS signature system.
	AlgorithmHSS Algorithm = "hss"
	// AlgorithmLMS selects a single-level LMS signature tree.
	AlgorithmLMS Algorithm = "lms"
	// AlgorithmXMSS selects the stateful XMSS signature system.
	AlgorithmXMSS Algorithm = "xmss"
	// AlgorithmXMSSMT selects the multi-tree XMSSMT signature system.
	AlgorithmXMSSMT Algorithm = "xmssmt"
	// AlgorithmDilithium2 selects the legacy or vendor Dilithium level-2 profile.
	AlgorithmDilithium2 Algorithm = "dilithium-2"
	// AlgorithmDilithium3 selects the legacy or vendor Dilithium level-3 profile.
	AlgorithmDilithium3 Algorithm = "dilithium-3"
	// AlgorithmDilithium5 selects the legacy or vendor Dilithium level-5 profile.
	AlgorithmDilithium5 Algorithm = "dilithium-5"
	// AlgorithmKyber512 selects the legacy or vendor Kyber-512 KEM profile.
	AlgorithmKyber512 Algorithm = "kyber-512"
	// AlgorithmKyber768 selects the legacy or vendor Kyber-768 KEM profile.
	AlgorithmKyber768 Algorithm = "kyber-768"
	// AlgorithmKyber1024 selects the legacy or vendor Kyber-1024 KEM profile.
	AlgorithmKyber1024 Algorithm = "kyber-1024"
	// AlgorithmFalcon512 selects the vendor Falcon-512 signature profile.
	AlgorithmFalcon512 Algorithm = "falcon-512"
	// AlgorithmFalcon1024 selects the vendor Falcon-1024 signature profile.
	AlgorithmFalcon1024 Algorithm = "falcon-1024"
	// AlgorithmSPHINCSPlus selects a vendor SPHINCS+ signature profile.
	AlgorithmSPHINCSPlus Algorithm = "sphincs-plus"
	// AlgorithmComposite selects a vendor-defined composite key or signature scheme.
	AlgorithmComposite Algorithm = "composite"
	// AlgorithmHybrid selects a vendor-defined hybrid key or signature scheme.
	AlgorithmHybrid Algorithm = "hybrid"
	// AlgorithmMLDSA44 selects the standardized ML-DSA-44 parameter set.
	AlgorithmMLDSA44 Algorithm = "ml-dsa-44"
	// AlgorithmMLDSA65 selects the standardized ML-DSA-65 parameter set.
	AlgorithmMLDSA65 Algorithm = "ml-dsa-65"
	// AlgorithmMLDSA87 selects the standardized ML-DSA-87 parameter set.
	AlgorithmMLDSA87 Algorithm = "ml-dsa-87"
	// AlgorithmMLKEM512 selects the standardized ML-KEM-512 parameter set.
	AlgorithmMLKEM512 Algorithm = "ml-kem-512"
	// AlgorithmMLKEM768 selects the standardized ML-KEM-768 parameter set.
	AlgorithmMLKEM768 Algorithm = "ml-kem-768"
	// AlgorithmMLKEM1024 selects the standardized ML-KEM-1024 parameter set.
	AlgorithmMLKEM1024 Algorithm = "ml-kem-1024"
	// AlgorithmSLHDSASHA2128S selects SLH-DSA SHA2-128s.
	AlgorithmSLHDSASHA2128S Algorithm = "slh-dsa-sha2-128s"
	// AlgorithmSLHDSASHAKE128S selects SLH-DSA SHAKE-128s.
	AlgorithmSLHDSASHAKE128S Algorithm = "slh-dsa-shake-128s"
	// AlgorithmSLHDSASHA2128F selects SLH-DSA SHA2-128f.
	AlgorithmSLHDSASHA2128F Algorithm = "slh-dsa-sha2-128f"
	// AlgorithmSLHDSASHAKE128F selects SLH-DSA SHAKE-128f.
	AlgorithmSLHDSASHAKE128F Algorithm = "slh-dsa-shake-128f"
	// AlgorithmSLHDSASHA2192S selects SLH-DSA SHA2-192s.
	AlgorithmSLHDSASHA2192S Algorithm = "slh-dsa-sha2-192s"
	// AlgorithmSLHDSASHAKE192S selects SLH-DSA SHAKE-192s.
	AlgorithmSLHDSASHAKE192S Algorithm = "slh-dsa-shake-192s"
	// AlgorithmSLHDSASHA2192F selects SLH-DSA SHA2-192f.
	AlgorithmSLHDSASHA2192F Algorithm = "slh-dsa-sha2-192f"
	// AlgorithmSLHDSASHAKE192F selects SLH-DSA SHAKE-192f.
	AlgorithmSLHDSASHAKE192F Algorithm = "slh-dsa-shake-192f"
	// AlgorithmSLHDSASHA2256S selects SLH-DSA SHA2-256s.
	AlgorithmSLHDSASHA2256S Algorithm = "slh-dsa-sha2-256s"
	// AlgorithmSLHDSASHAKE256S selects SLH-DSA SHAKE-256s.
	AlgorithmSLHDSASHAKE256S Algorithm = "slh-dsa-shake-256s"
	// AlgorithmSLHDSASHA2256F selects SLH-DSA SHA2-256f.
	AlgorithmSLHDSASHA2256F Algorithm = "slh-dsa-sha2-256f"
	// AlgorithmSLHDSASHAKE256F selects SLH-DSA SHAKE-256f.
	AlgorithmSLHDSASHAKE256F Algorithm = "slh-dsa-shake-256f"
)

// Operation identifies the high-level action for mechanism and template routing.
type Operation string

const (
	// OperationGenerate requests key or key-pair generation.
	OperationGenerate Operation = "generate"
	// OperationSign requests creation of a signature or MAC.
	OperationSign Operation = "sign"
	// OperationVerify requests verification of a signature or MAC.
	OperationVerify Operation = "verify"
	// OperationEncrypt requests public-key or symmetric encryption.
	OperationEncrypt Operation = "encrypt"
	// OperationDecrypt requests private-key or symmetric decryption.
	OperationDecrypt Operation = "decrypt"
	// OperationWrap requests export of a key under a wrapping key.
	OperationWrap Operation = "wrap"
	// OperationUnwrap requests import of wrapped key material.
	OperationUnwrap Operation = "unwrap"
	// OperationDerive requests creation of a key from an existing key.
	OperationDerive Operation = "derive"
	// OperationEncapsulate requests KEM encapsulation for a public key.
	OperationEncapsulate Operation = "encapsulate"
	// OperationDecapsulate requests KEM decapsulation with a private key.
	OperationDecapsulate Operation = "decapsulate"
)

// RSAPadding selects the RSA encoding used for signing or encryption.
type RSAPadding string

const (
	// RSAPaddingPKCS1v15 selects PKCS #1 v1.5 signature or encryption encoding.
	RSAPaddingPKCS1v15 RSAPadding = "pkcs1v15"
	// RSAPaddingPSS selects RSASSA-PSS signatures.
	RSAPaddingPSS RSAPadding = "pss"
	// RSAPaddingOAEP selects RSAES-OAEP encryption.
	RSAPaddingOAEP RSAPadding = "oaep"
	// RSAPaddingRaw selects the unencoded CKM_RSA_X_509 primitive.
	RSAPaddingRaw RSAPadding = "raw"
)

// CipherMode selects the block or AEAD mode used with an AES key.
type CipherMode string

const (
	// CipherModeGCM selects authenticated AES-GCM.
	CipherModeGCM CipherMode = "gcm"
	// CipherModeCBC selects padded AES-CBC.
	CipherModeCBC CipherMode = "cbc"
	// CipherModeCTR selects AES counter mode with a 128-bit counter block.
	CipherModeCTR CipherMode = "ctr"
)

// Intent describes what the caller wants, independent of a vendor mechanism
// number. Route resolves it against the detected token and adapter.
type Intent struct {
	// Operation is the action for which a mechanism must be selected.
	Operation Operation
	// Algorithm is the vendor-neutral algorithm requested by the application.
	Algorithm Algorithm
	// Hash identifies either a combined hash-and-sign mechanism or the digest
	// algorithm used by a prehashed operation. A zero value means direct-message
	// processing for algorithms that support it.
	Hash crypto.Hash
	// Prehashed states that the supplied data is already the digest named by Hash.
	Prehashed bool
	// ExternalMu selects a vendor mechanism that accepts a precomputed ML-DSA mu.
	// PKCS #11 3.2 does not assign a standard mechanism identifier for this mode.
	ExternalMu bool
	// RSAPadding selects the RSA signature or encryption encoding.
	RSAPadding RSAPadding
	// PSSSaltLength is the requested RSA-PSS salt length in bytes. Non-positive
	// values are resolved by the higher-level signing API.
	PSSSaltLength int
	// OAEPLabel is copied into the RSA-OAEP source-data parameter.
	OAEPLabel []byte
	// CipherMode selects the AES mode. Its zero value resolves to GCM.
	CipherMode CipherMode
	// IV contains the GCM IV, CBC IV, or complete CTR counter block.
	IV []byte
	// AAD is authenticated but not encrypted by an AEAD mechanism.
	AAD []byte
	// TagBits is the requested authentication-tag length in bits.
	TagBits uint
	// Context is the domain-separation context for EdDSA and standardized PQC signatures.
	Context []byte
	// Hedge controls deterministic versus randomized standardized PQC signing.
	Hedge HedgeMode
	// MechanismOverride bypasses automatic standard-first mechanism selection.
	MechanismOverride *uint
	// MechanismParameter replaces the parameter synthesized by the router. It is
	// intended for typed raw parameters or an vendors/<vendor> parameter encoder.
	MechanismParameter any
}

// RouteReplay controls whether a VendorModule changes the root driver's normal
// replay classification for a routed operation.
type RouteReplay uint8

const (
	// RouteReplayDefault preserves the generic operation policy.
	RouteReplayDefault RouteReplay = iota
	// RouteReplaySafe explicitly permits replay of the complete operation.
	RouteReplaySafe
	// RouteReplayNever disables replay, including for operations that are usually
	// idempotent, because the provider may consume or mutate persistent state.
	RouteReplayNever
)

// RouteExecution carries exceptional managed-session requirements selected by a
// VendorModule. The zero value uses the normal operation policy.
type RouteExecution struct {
	// ReadWrite forces the operation onto a read/write session.
	ReadWrite bool
	// Replay overrides the generic replay classification when non-zero.
	Replay RouteReplay
}

// Route is a fully resolved PKCS#11 plan. PublicTemplate and PrivateTemplate
// contain only algorithm-mandated attributes; policy attributes are merged by
// the high-level key-generation API.
type Route struct {
	// Intent is the normalized intent used to construct this route.
	Intent Intent
	// Mechanism is ready to pass to the raw package. Its parameter may be a
	// standard typed parameter or vendor-specific encoded bytes.
	Mechanism *raw.Mechanism
	// MechanismSource identifies standard selection, a vendor adapter, or an
	// explicit caller override.
	MechanismSource string
	// KeyType is the CKK_* identifier selected for generated or located objects.
	KeyType uint
	// ParameterSet is the CKP_* or vendor parameter-set identifier, when applicable.
	ParameterSet uint
	// PublicTemplate contains algorithm-mandated public-key attributes only.
	PublicTemplate []*raw.Attribute
	// PrivateTemplate contains algorithm-mandated private-key attributes only.
	PrivateTemplate []*raw.Attribute
	// SecretTemplate contains algorithm-mandated secret-key attributes only.
	SecretTemplate []*raw.Attribute
	// Reasons records human-readable diagnostics for the selected route.
	Reasons []string

	// Execution contains exceptional session and replay requirements selected by
	// a VendorModule. The zero value uses normal managed behavior.
	Execution RouteExecution
	// OmitParameterSetAttribute indicates that the provider carries its parameter
	// set in the mechanism parameter rather than CKA_PARAMETER_SET.
	OmitParameterSetAttribute bool
	// VendorData is opaque state owned by the selected VendorModule. The root
	// driver never interprets it.
	VendorData any
}

type algorithmSpec struct {
	KeyType                  uint
	KeyTypeAlias             string
	RequireKeyTypeAlias      bool
	KeyPair                  bool
	KeyPairMechanism         uint
	KeyPairMechanismSet      bool
	KeyPairAlias             string
	Secret                   bool
	SecretKeyMechanism       uint
	SecretKeyMechanismSet    bool
	SecretKeyAlias           string
	ParameterSet             uint
	ParameterSetAlias        string
	RequireParameterSetAlias bool
	ECParams                 []byte
	SecretBytes              uint
	SignMechanisms           []uint
	SignAlias                string
	EncryptionMechanisms     []uint
	DeriveMechanisms         []uint
	KEMMechanisms            []uint
	KEMAlias                 string
}

func oidBytes(values ...int) []byte {
	encoded, err := asn1.Marshal(asn1.ObjectIdentifier(values))
	if err != nil {
		panic(err)
	}
	return encoded
}

// algorithmSpecs is the declarative standard-first routing catalog. Vendor
// adapters may supply aliases for entries whose numeric identifiers are not
// standardized, but they do not replace the algorithm-level public API.
var algorithmSpecs = map[Algorithm]algorithmSpec{
	AlgorithmRSA:        {KeyType: raw.CKK_RSA, KeyTypeAlias: "rsa", KeyPair: true, KeyPairMechanism: raw.CKM_RSA_PKCS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "rsa-key-pair-gen", SignMechanisms: []uint{raw.CKM_RSA_PKCS, raw.CKM_RSA_PKCS_PSS, raw.CKM_SHA256_RSA_PKCS, raw.CKM_SHA384_RSA_PKCS, raw.CKM_SHA512_RSA_PKCS, raw.CKM_SHA256_RSA_PKCS_PSS, raw.CKM_SHA384_RSA_PKCS_PSS, raw.CKM_SHA512_RSA_PKCS_PSS}, EncryptionMechanisms: []uint{raw.CKM_RSA_PKCS, raw.CKM_RSA_PKCS_OAEP, raw.CKM_RSA_X_509}},
	AlgorithmECDSAP256:  {KeyType: raw.CKK_EC, KeyTypeAlias: "ec", KeyPair: true, KeyPairMechanism: raw.CKM_EC_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ec-key-pair-gen", ECParams: oidBytes(1, 2, 840, 10045, 3, 1, 7), SignMechanisms: []uint{raw.CKM_ECDSA, raw.CKM_ECDSA_SHA256}},
	AlgorithmECDSAP384:  {KeyType: raw.CKK_EC, KeyTypeAlias: "ec", KeyPair: true, KeyPairMechanism: raw.CKM_EC_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ec-key-pair-gen", ECParams: oidBytes(1, 3, 132, 0, 34), SignMechanisms: []uint{raw.CKM_ECDSA, raw.CKM_ECDSA_SHA384}},
	AlgorithmECDSAP521:  {KeyType: raw.CKK_EC, KeyTypeAlias: "ec", KeyPair: true, KeyPairMechanism: raw.CKM_EC_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ec-key-pair-gen", ECParams: oidBytes(1, 3, 132, 0, 35), SignMechanisms: []uint{raw.CKM_ECDSA, raw.CKM_ECDSA_SHA512}},
	AlgorithmEd25519:    {KeyType: raw.CKK_EC_EDWARDS, KeyTypeAlias: "ec-edwards", KeyPair: true, KeyPairMechanism: raw.CKM_EC_EDWARDS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ec-edwards-key-pair-gen", ECParams: oidBytes(1, 3, 101, 112), SignMechanisms: []uint{raw.CKM_EDDSA}},
	AlgorithmEd448:      {KeyType: raw.CKK_EC_EDWARDS, KeyTypeAlias: "ec-edwards", KeyPair: true, KeyPairMechanism: raw.CKM_EC_EDWARDS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ec-edwards-key-pair-gen", ECParams: oidBytes(1, 3, 101, 113), SignMechanisms: []uint{raw.CKM_EDDSA}},
	AlgorithmAES128:     {KeyType: raw.CKK_AES, KeyTypeAlias: "aes", Secret: true, SecretKeyMechanism: raw.CKM_AES_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "aes-key-gen", SecretBytes: 16, EncryptionMechanisms: []uint{raw.CKM_AES_GCM, raw.CKM_AES_CBC_PAD, raw.CKM_AES_CTR}},
	AlgorithmAES192:     {KeyType: raw.CKK_AES, KeyTypeAlias: "aes", Secret: true, SecretKeyMechanism: raw.CKM_AES_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "aes-key-gen", SecretBytes: 24, EncryptionMechanisms: []uint{raw.CKM_AES_GCM, raw.CKM_AES_CBC_PAD, raw.CKM_AES_CTR}},
	AlgorithmAES256:     {KeyType: raw.CKK_AES, KeyTypeAlias: "aes", Secret: true, SecretKeyMechanism: raw.CKM_AES_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "aes-key-gen", SecretBytes: 32, EncryptionMechanisms: []uint{raw.CKM_AES_GCM, raw.CKM_AES_CBC_PAD, raw.CKM_AES_CTR}},
	AlgorithmHMACSHA256: {KeyType: raw.CKK_GENERIC_SECRET, KeyTypeAlias: "generic-secret", Secret: true, SecretKeyMechanism: raw.CKM_GENERIC_SECRET_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "generic-secret-key-gen", SecretBytes: 32, SignMechanisms: []uint{raw.CKM_SHA256_HMAC}},
	AlgorithmHMACSHA384: {KeyType: raw.CKK_GENERIC_SECRET, KeyTypeAlias: "generic-secret", Secret: true, SecretKeyMechanism: raw.CKM_GENERIC_SECRET_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "generic-secret-key-gen", SecretBytes: 48, SignMechanisms: []uint{raw.CKM_SHA384_HMAC}},
	AlgorithmHMACSHA512: {KeyType: raw.CKK_GENERIC_SECRET, KeyTypeAlias: "generic-secret", Secret: true, SecretKeyMechanism: raw.CKM_GENERIC_SECRET_KEY_GEN, SecretKeyMechanismSet: true, SecretKeyAlias: "generic-secret-key-gen", SecretBytes: 64, SignMechanisms: []uint{raw.CKM_SHA512_HMAC}},
	AlgorithmHSS:        {KeyType: raw.CKK_HSS, KeyTypeAlias: "hss", KeyPair: true, KeyPairMechanism: raw.CKM_HSS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "hss-key-pair-gen", SignMechanisms: []uint{raw.CKM_HSS}},
	AlgorithmLMS:        {KeyType: raw.CKK_HSS, KeyTypeAlias: "hss", KeyPair: true, KeyPairMechanism: raw.CKM_HSS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "lms-key-pair-gen", SignMechanisms: []uint{raw.CKM_HSS}},
	AlgorithmXMSS:       {KeyType: raw.CKK_XMSS, KeyTypeAlias: "xmss", KeyPair: true, KeyPairMechanism: raw.CKM_XMSS_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "xmss-key-pair-gen", SignMechanisms: []uint{raw.CKM_XMSS}},
	AlgorithmXMSSMT:     {KeyType: raw.CKK_XMSSMT, KeyTypeAlias: "xmssmt", KeyPair: true, KeyPairMechanism: raw.CKM_XMSSMT_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "xmssmt-key-pair-gen", SignMechanisms: []uint{raw.CKM_XMSSMT}},
	AlgorithmMLDSA44:    {KeyType: raw.CKK_ML_DSA, KeyTypeAlias: "ml-dsa", KeyPair: true, KeyPairMechanism: raw.CKM_ML_DSA_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-dsa-key-pair-gen", ParameterSet: raw.CKP_ML_DSA_44, ParameterSetAlias: "ml-dsa-44", SignMechanisms: []uint{raw.CKM_ML_DSA, raw.CKM_HASH_ML_DSA}},
	AlgorithmMLDSA65:    {KeyType: raw.CKK_ML_DSA, KeyTypeAlias: "ml-dsa", KeyPair: true, KeyPairMechanism: raw.CKM_ML_DSA_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-dsa-key-pair-gen", ParameterSet: raw.CKP_ML_DSA_65, ParameterSetAlias: "ml-dsa-65", SignMechanisms: []uint{raw.CKM_ML_DSA, raw.CKM_HASH_ML_DSA}},
	AlgorithmMLDSA87:    {KeyType: raw.CKK_ML_DSA, KeyTypeAlias: "ml-dsa", KeyPair: true, KeyPairMechanism: raw.CKM_ML_DSA_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-dsa-key-pair-gen", ParameterSet: raw.CKP_ML_DSA_87, ParameterSetAlias: "ml-dsa-87", SignMechanisms: []uint{raw.CKM_ML_DSA, raw.CKM_HASH_ML_DSA}},
	AlgorithmMLKEM512:   {KeyType: raw.CKK_ML_KEM, KeyTypeAlias: "ml-kem", KeyPair: true, KeyPairMechanism: raw.CKM_ML_KEM_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-kem-key-pair-gen", ParameterSet: raw.CKP_ML_KEM_512, ParameterSetAlias: "ml-kem-512", KEMMechanisms: []uint{raw.CKM_ML_KEM}},
	AlgorithmMLKEM768:   {KeyType: raw.CKK_ML_KEM, KeyTypeAlias: "ml-kem", KeyPair: true, KeyPairMechanism: raw.CKM_ML_KEM_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-kem-key-pair-gen", ParameterSet: raw.CKP_ML_KEM_768, ParameterSetAlias: "ml-kem-768", KEMMechanisms: []uint{raw.CKM_ML_KEM}},
	AlgorithmMLKEM1024:  {KeyType: raw.CKK_ML_KEM, KeyTypeAlias: "ml-kem", KeyPair: true, KeyPairMechanism: raw.CKM_ML_KEM_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "ml-kem-key-pair-gen", ParameterSet: raw.CKP_ML_KEM_1024, ParameterSetAlias: "ml-kem-1024", KEMMechanisms: []uint{raw.CKM_ML_KEM}},

	// These legacy or vendor-defined algorithms intentionally contain no
	// undocumented numeric identifiers. A selected vendor adapter supplies the
	// mechanism, key-type, and parameter-set aliases, or a caller can use an
	// explicit mechanism override.
	AlgorithmDilithium2:  {KeyTypeAlias: "dilithium", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "dilithium-key-pair-gen", ParameterSetAlias: "dilithium-2", RequireParameterSetAlias: true, SignAlias: "dilithium"},
	AlgorithmDilithium3:  {KeyTypeAlias: "dilithium", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "dilithium-key-pair-gen", ParameterSetAlias: "dilithium-3", RequireParameterSetAlias: true, SignAlias: "dilithium"},
	AlgorithmDilithium5:  {KeyTypeAlias: "dilithium", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "dilithium-key-pair-gen", ParameterSetAlias: "dilithium-5", RequireParameterSetAlias: true, SignAlias: "dilithium"},
	AlgorithmKyber512:    {KeyTypeAlias: "kyber", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "kyber-key-pair-gen", ParameterSetAlias: "kyber-512", RequireParameterSetAlias: true, KEMAlias: "kyber"},
	AlgorithmKyber768:    {KeyTypeAlias: "kyber", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "kyber-key-pair-gen", ParameterSetAlias: "kyber-768", RequireParameterSetAlias: true, KEMAlias: "kyber"},
	AlgorithmKyber1024:   {KeyTypeAlias: "kyber", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "kyber-key-pair-gen", ParameterSetAlias: "kyber-1024", RequireParameterSetAlias: true, KEMAlias: "kyber"},
	AlgorithmFalcon512:   {KeyTypeAlias: "falcon", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "falcon-key-pair-gen", ParameterSetAlias: "falcon-512", RequireParameterSetAlias: true, SignAlias: "falcon"},
	AlgorithmFalcon1024:  {KeyTypeAlias: "falcon", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "falcon-key-pair-gen", ParameterSetAlias: "falcon-1024", RequireParameterSetAlias: true, SignAlias: "falcon"},
	AlgorithmSPHINCSPlus: {KeyTypeAlias: "sphincs-plus", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "sphincs-plus-key-pair-gen", SignAlias: "sphincs-plus"},
	AlgorithmComposite:   {KeyTypeAlias: "composite", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "composite-key-pair-gen", SignAlias: "composite"},
	AlgorithmHybrid:      {KeyTypeAlias: "hybrid", RequireKeyTypeAlias: true, KeyPair: true, KeyPairAlias: "hybrid-key-pair-gen", SignAlias: "hybrid"},
}

func init() {
	// All SLH-DSA variants share the same key type and mechanisms; only the
	// standardized parameter-set selector differs. Populate them from one table
	// to keep generation, signing, and capability discovery consistent.
	for algorithm, parameterSet := range map[Algorithm]uint{
		AlgorithmSLHDSASHA2128S:  raw.CKP_SLH_DSA_SHA2_128S,
		AlgorithmSLHDSASHAKE128S: raw.CKP_SLH_DSA_SHAKE_128S,
		AlgorithmSLHDSASHA2128F:  raw.CKP_SLH_DSA_SHA2_128F,
		AlgorithmSLHDSASHAKE128F: raw.CKP_SLH_DSA_SHAKE_128F,
		AlgorithmSLHDSASHA2192S:  raw.CKP_SLH_DSA_SHA2_192S,
		AlgorithmSLHDSASHAKE192S: raw.CKP_SLH_DSA_SHAKE_192S,
		AlgorithmSLHDSASHA2192F:  raw.CKP_SLH_DSA_SHA2_192F,
		AlgorithmSLHDSASHAKE192F: raw.CKP_SLH_DSA_SHAKE_192F,
		AlgorithmSLHDSASHA2256S:  raw.CKP_SLH_DSA_SHA2_256S,
		AlgorithmSLHDSASHAKE256S: raw.CKP_SLH_DSA_SHAKE_256S,
		AlgorithmSLHDSASHA2256F:  raw.CKP_SLH_DSA_SHA2_256F,
		AlgorithmSLHDSASHAKE256F: raw.CKP_SLH_DSA_SHAKE_256F,
	} {
		algorithmSpecs[algorithm] = algorithmSpec{KeyType: raw.CKK_SLH_DSA, KeyTypeAlias: "slh-dsa", KeyPair: true, KeyPairMechanism: raw.CKM_SLH_DSA_KEY_PAIR_GEN, KeyPairMechanismSet: true, KeyPairAlias: "slh-dsa-key-pair-gen", ParameterSet: parameterSet, ParameterSetAlias: string(algorithm), SignMechanisms: []uint{raw.CKM_SLH_DSA, raw.CKM_HASH_SLH_DSA}}
	}
}

// AllAlgorithms returns every algorithm understood by the high-level router in stable lexical order.
func AllAlgorithms() []Algorithm {
	result := make([]Algorithm, 0, len(algorithmSpecs))
	for algorithm := range algorithmSpecs {
		result = append(result, algorithm)
	}
	slices.Sort(result)
	return result
}

func mechanismAlias(definition adapterDefinition, name string) (uint, bool) {
	if definition.identifiers.mechanisms == nil {
		return 0, false
	}
	value, ok := definition.identifiers.mechanisms[strings.ToLower(name)]
	return uint(value), ok
}

func keyTypeAlias(definition adapterDefinition, name string, standard uint) (uint, bool) {
	if definition.identifiers.keyTypes != nil {
		if value, ok := definition.identifiers.keyTypes[strings.ToLower(name)]; ok {
			return uint(value), true
		}
	}
	return standard, false
}

func parameterSetAlias(definition adapterDefinition, name string, standard uint) (uint, bool) {
	if definition.identifiers.parameterSets != nil {
		if value, ok := definition.identifiers.parameterSets[strings.ToLower(name)]; ok {
			return uint(value), true
		}
	}
	return standard, false
}

// chooseMechanism implements the driver's standard-first promise. A positively
// detected adapter may provide a proprietary fallback, but a correctly
// advertised standard mechanism wins unless that adapter explicitly requires
// its vendor identifier for compatibility.
func chooseMechanism(device Device, standard uint, alias string, requiredFlag uint) (uint, string, []string, error) {
	definition := device.definition
	vendor, hasVendor := mechanismAlias(definition, alias)
	standardCandidate := func(id uint) bool {
		info, ok := device.Fingerprint.Mechanisms[raw.MechanismType(id)]
		return ok && (requiredFlag == 0 || info.Flags&requiredFlag != 0)
	}
	vendorCandidate := func(id uint) bool {
		info, ok := device.Fingerprint.Mechanisms[raw.MechanismType(id)]
		// Several vendor modules enumerate proprietary mechanisms but report a
		// zero capability mask. Once the HSM family has been positively detected,
		// presence is enough for a built-in, documented vendor mapping. Standard
		// mechanisms still require their normative CKF_* capability flag.
		return ok && (requiredFlag == 0 || info.Flags == 0 || info.Flags&requiredFlag != 0)
	}
	if definition.preferVendorIdentifiers && hasVendor && vendorCandidate(vendor) {
		return vendor, "vendor-adapter", []string{"vendor alias preferred and advertised"}, nil
	}
	if standardCandidate(standard) {
		return standard, "pkcs11-standard", []string{"standard mechanism advertised with required flags"}, nil
	}
	if hasVendor && vendorCandidate(vendor) {
		return vendor, "vendor-adapter", []string{"standard mechanism unavailable; advertised vendor alias selected"}, nil
	}
	if hasVendor && device.plan.mechanisms.allowUnadvertisedAliases {
		return vendor, "vendor-adapter-unadvertised", []string{"internal vendor adapter permits non-standard route"}, nil
	}
	return 0, "", nil, fmt.Errorf("pkcs11: %s has neither standard mechanism 0x%x nor usable alias %q for %s", device.Fingerprint.Token.Label, standard, alias, requiredFlagName(requiredFlag))
}

// chooseVendorMechanism resolves an operation that has no standard mechanism
// candidate. It is intentionally stricter than a caller override: the alias must
// come from the selected adapter catalog and normally must be advertised.
func chooseVendorMechanism(device Device, alias string, requiredFlag uint) (uint, string, []string, error) {
	definition := device.definition
	vendor, ok := definition.identifiers.mechanisms[alias]
	if !ok {
		return 0, "", nil, fmt.Errorf("pkcs11: %s requires vendor mechanism alias %q, but adapter %q does not define it", device.Fingerprint.Token.Label, alias, definition.name)
	}
	id := uint(vendor)
	if info, advertised := device.Fingerprint.Mechanisms[raw.MechanismType(id)]; advertised {
		if requiredFlag == 0 || info.Flags == 0 || info.Flags&requiredFlag != 0 {
			return id, "vendor-adapter", []string{"vendor-only mechanism advertised with required flags"}, nil
		}
		return 0, "", nil, fmt.Errorf("pkcs11: vendor mechanism alias %q (0x%x) lacks %s capability", alias, id, requiredFlagName(requiredFlag))
	}
	if device.plan.mechanisms.allowUnadvertisedAliases {
		return id, "vendor-adapter-unadvertised", []string{"internal adapter permits unadvertised vendor-only mechanism"}, nil
	}
	return 0, "", nil, fmt.Errorf("pkcs11: vendor mechanism alias %q (0x%x) is not advertised by token %q", alias, id, device.Fingerprint.Token.Label)
}

// IsStatefulSignatureAlgorithm reports whether signing consumes persistent key
// state. Managed signing never retries these operations.
func IsStatefulSignatureAlgorithm(algorithm Algorithm) bool {
	switch algorithm {
	case AlgorithmHSS, AlgorithmLMS, AlgorithmXMSS, AlgorithmXMSSMT:
		return true
	default:
		return false
	}
}

func requiredFlagName(flag uint) string {
	switch flag {
	case raw.CKF_GENERATE_KEY_PAIR:
		return "key-pair generation"
	case raw.CKF_GENERATE:
		return "key generation"
	case raw.CKF_SIGN:
		return "signing"
	case raw.CKF_VERIFY:
		return "verification"
	case raw.CKF_ENCRYPT:
		return "encryption"
	case raw.CKF_DECRYPT:
		return "decryption"
	case raw.CKF_ENCAPSULATE:
		return "encapsulation"
	case raw.CKF_DECAPSULATE:
		return "decapsulation"
	default:
		return fmt.Sprintf("flag 0x%x", flag)
	}
}

func hashMechanisms(hash crypto.Hash, pss bool) (mechanism, hashMechanism, mgf uint, err error) {
	switch hash {
	case crypto.SHA1:
		if pss {
			return raw.CKM_SHA1_RSA_PKCS_PSS, raw.CKM_SHA_1, raw.CKG_MGF1_SHA1, nil
		}
		return raw.CKM_SHA1_RSA_PKCS, raw.CKM_SHA_1, raw.CKG_MGF1_SHA1, nil
	case crypto.SHA224:
		if pss {
			return raw.CKM_SHA224_RSA_PKCS_PSS, raw.CKM_SHA224, raw.CKG_MGF1_SHA224, nil
		}
		return raw.CKM_SHA224_RSA_PKCS, raw.CKM_SHA224, raw.CKG_MGF1_SHA224, nil
	case crypto.SHA256:
		if pss {
			return raw.CKM_SHA256_RSA_PKCS_PSS, raw.CKM_SHA256, raw.CKG_MGF1_SHA256, nil
		}
		return raw.CKM_SHA256_RSA_PKCS, raw.CKM_SHA256, raw.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		if pss {
			return raw.CKM_SHA384_RSA_PKCS_PSS, raw.CKM_SHA384, raw.CKG_MGF1_SHA384, nil
		}
		return raw.CKM_SHA384_RSA_PKCS, raw.CKM_SHA384, raw.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		if pss {
			return raw.CKM_SHA512_RSA_PKCS_PSS, raw.CKM_SHA512, raw.CKG_MGF1_SHA512, nil
		}
		return raw.CKM_SHA512_RSA_PKCS, raw.CKM_SHA512, raw.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, 0, fmt.Errorf("pkcs11: unsupported hash %v", hash)
	}
}

func digestMechanism(hash crypto.Hash) (uint, error) {
	if hash == 0 {
		hash = crypto.SHA256
	}
	switch hash {
	case crypto.SHA1:
		return raw.CKM_SHA_1, nil
	case crypto.SHA224:
		return raw.CKM_SHA224, nil
	case crypto.SHA256:
		return raw.CKM_SHA256, nil
	case crypto.SHA384:
		return raw.CKM_SHA384, nil
	case crypto.SHA512:
		return raw.CKM_SHA512, nil
	case crypto.SHA512_224:
		return raw.CKM_SHA512_224, nil
	case crypto.SHA512_256:
		return raw.CKM_SHA512_256, nil
	case crypto.SHA3_224:
		return raw.CKM_SHA3_224, nil
	case crypto.SHA3_256:
		return raw.CKM_SHA3_256, nil
	case crypto.SHA3_384:
		return raw.CKM_SHA3_384, nil
	case crypto.SHA3_512:
		return raw.CKM_SHA3_512, nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported hash %v", hash)
	}
}

func pqcHashMechanism(hash crypto.Hash, slh bool) (uint, error) {
	if slh {
		switch hash {
		case crypto.SHA224:
			return raw.CKM_HASH_SLH_DSA_SHA224, nil
		case crypto.SHA256:
			return raw.CKM_HASH_SLH_DSA_SHA256, nil
		case crypto.SHA384:
			return raw.CKM_HASH_SLH_DSA_SHA384, nil
		case crypto.SHA512:
			return raw.CKM_HASH_SLH_DSA_SHA512, nil
		default:
			return 0, fmt.Errorf("pkcs11: unsupported SLH-DSA hash %v", hash)
		}
	}
	switch hash {
	case crypto.SHA224:
		return raw.CKM_HASH_ML_DSA_SHA224, nil
	case crypto.SHA256:
		return raw.CKM_HASH_ML_DSA_SHA256, nil
	case crypto.SHA384:
		return raw.CKM_HASH_ML_DSA_SHA384, nil
	case crypto.SHA512:
		return raw.CKM_HASH_ML_DSA_SHA512, nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported ML-DSA hash %v", hash)
	}
}

func resolvePQCSignature(hash crypto.Hash, prehashed, slh bool, hedge HedgeMode, context []byte) (uint, string, any, error) {
	if prehashed && hash == 0 {
		return 0, "", nil, fmt.Errorf("pkcs11: PQC prehash routing requires an explicit hash")
	}
	pure, externallyHashed, alias := raw.CKM_ML_DSA, raw.CKM_HASH_ML_DSA, "ml-dsa"
	if slh {
		pure, externallyHashed, alias = raw.CKM_SLH_DSA, raw.CKM_HASH_SLH_DSA, "slh-dsa"
	}
	if hash == 0 {
		return pure, alias, raw.SignAdditionalContext{Hedge: raw.HedgeMode(hedge), Context: context}, nil
	}
	if prehashed {
		hashMechanism, err := digestMechanism(hash)
		if err != nil {
			return 0, "", nil, err
		}
		return externallyHashed, "hash-" + alias, raw.HashSignAdditionalContext{Hedge: raw.HedgeMode(hedge), Context: context, Hash: hashMechanism}, nil
	}
	mechanism, err := pqcHashMechanism(hash, slh)
	if err != nil {
		return 0, "", nil, err
	}
	return mechanism, strings.ToLower(hash.String()) + "-" + alias, raw.SignAdditionalContext{Hedge: raw.HedgeMode(hedge), Context: context}, nil
}

func ecdsaMechanism(algorithm Algorithm, hash crypto.Hash, prehashed bool) (uint, error) {
	if prehashed || hash == 0 {
		return raw.CKM_ECDSA, nil
	}
	switch hash {
	case crypto.SHA1:
		return raw.CKM_ECDSA_SHA1, nil
	case crypto.SHA224:
		return raw.CKM_ECDSA_SHA224, nil
	case crypto.SHA256:
		return raw.CKM_ECDSA_SHA256, nil
	case crypto.SHA384:
		return raw.CKM_ECDSA_SHA384, nil
	case crypto.SHA512:
		return raw.CKM_ECDSA_SHA512, nil
	default:
		return 0, fmt.Errorf("pkcs11: unsupported ECDSA hash %v for %s", hash, algorithm)
	}
}

// ResolveRoute converts an algorithm intent into mechanism and template data.
//
// Resolution is deterministic and side-effect free. It normalizes defaults,
// verifies required aliases, chooses a standard mechanism before a vendor
// fallback, applies the selected adapter's parameter translation, and finally
// constructs only the algorithm-mandated portion of an object template.
func ResolveRoute(device Device, intent Intent) (Route, error) {
	spec, ok := algorithmSpecs[intent.Algorithm]
	if !ok {
		return Route{}, fmt.Errorf("pkcs11: unsupported algorithm %q", intent.Algorithm)
	}
	if intent.Hash == 0 && intent.Algorithm == AlgorithmRSA {
		intent.Hash = crypto.SHA256
	}
	if intent.TagBits == 0 && strings.HasPrefix(string(intent.Algorithm), "aes-") && (intent.CipherMode == "" || intent.CipherMode == CipherModeGCM) {
		intent.TagBits = 128
	}
	vendorKeyType, hasKeyTypeAlias := keyTypeAlias(device.definition, spec.KeyTypeAlias, spec.KeyType)
	vendorParameterSet, hasParameterSetAlias := parameterSetAlias(device.definition, spec.ParameterSetAlias, spec.ParameterSet)
	if intent.Operation == OperationGenerate && spec.RequireKeyTypeAlias && !hasKeyTypeAlias {
		return Route{}, fmt.Errorf("pkcs11: adapter %q does not define key-type alias %q for %s", device.definition.name, spec.KeyTypeAlias, intent.Algorithm)
	}
	if intent.Operation == OperationGenerate && spec.RequireParameterSetAlias && !hasParameterSetAlias {
		return Route{}, fmt.Errorf("pkcs11: adapter %q does not define parameter-set alias %q for %s", device.definition.name, spec.ParameterSetAlias, intent.Algorithm)
	}
	keyType, parameterSet := spec.KeyType, spec.ParameterSet
	if spec.RequireKeyTypeAlias {
		keyType = vendorKeyType
	}
	if spec.RequireParameterSetAlias {
		parameterSet = vendorParameterSet
	}
	route := Route{Intent: intent, KeyType: keyType, ParameterSet: parameterSet}
	if intent.MechanismOverride != nil {
		// An explicit override is still wrapped in a Route so key-template defaults,
		// managed sessions, hooks, and recovery remain available to expert callers.
		route.Mechanism = raw.NewMechanism(*intent.MechanismOverride, intent.MechanismParameter)
		route.MechanismSource = "caller-override"
		route.Reasons = append(route.Reasons, "explicit mechanism override")
		adapted, err := adaptVendorRoute(device, route)
		if err != nil {
			return Route{}, err
		}
		route = adapted
		route.buildTemplates(spec)
		return route, nil
	}

	var standard, flag uint
	var alias string
	var parameter any
	aliasOnly := false
	switch intent.Operation {
	case OperationGenerate:
		if spec.KeyPair {
			standard, alias, flag = spec.KeyPairMechanism, spec.KeyPairAlias, raw.CKF_GENERATE_KEY_PAIR
			aliasOnly = !spec.KeyPairMechanismSet
		} else if spec.Secret {
			standard, alias, flag = spec.SecretKeyMechanism, spec.SecretKeyAlias, raw.CKF_GENERATE
			aliasOnly = !spec.SecretKeyMechanismSet
		} else {
			return Route{}, fmt.Errorf("pkcs11: %s cannot be generated", intent.Algorithm)
		}
	case OperationSign, OperationVerify:
		flag = raw.CKF_SIGN
		if intent.Operation == OperationVerify {
			flag = raw.CKF_VERIFY
		}
		switch intent.Algorithm {
		case AlgorithmRSA:
			padding := intent.RSAPadding
			if padding == "" {
				padding = RSAPaddingPSS
			}
			if intent.Prehashed {
				switch padding {
				case RSAPaddingPSS:
					standard, alias = raw.CKM_RSA_PKCS_PSS, "rsa-pss"
					_, hashAlg, mgf, err := hashMechanisms(intent.Hash, true)
					if err != nil {
						return Route{}, err
					}
					salt := intent.PSSSaltLength
					if salt <= 0 {
						salt = intent.Hash.Size()
					}
					parameter = raw.PSSParams{HashAlg: hashAlg, MGF: mgf, SaltLen: uint(salt)}
				case RSAPaddingPKCS1v15:
					standard, alias = raw.CKM_RSA_PKCS, "rsa-pkcs"
				case RSAPaddingRaw:
					standard, alias = raw.CKM_RSA_X_509, "rsa-x509"
				default:
					return Route{}, fmt.Errorf("pkcs11: RSA padding %q is not valid for signing", padding)
				}
			} else {
				var err error
				standard, _, _, err = hashMechanisms(intent.Hash, padding == RSAPaddingPSS)
				if err != nil {
					return Route{}, err
				}
				alias = strings.ToLower(fmt.Sprintf("%s-%s", intent.Hash.String(), padding))
				if padding == RSAPaddingPSS {
					_, hashAlg, mgf, _ := hashMechanisms(intent.Hash, true)
					salt := intent.PSSSaltLength
					if salt <= 0 {
						salt = intent.Hash.Size()
					}
					parameter = raw.PSSParams{HashAlg: hashAlg, MGF: mgf, SaltLen: uint(salt)}
				}
			}
		case AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521:
			var err error
			standard, err = ecdsaMechanism(intent.Algorithm, intent.Hash, intent.Prehashed)
			if err != nil {
				return Route{}, err
			}
			alias = "ecdsa"
		case AlgorithmEd25519:
			standard, alias = raw.CKM_EDDSA, "eddsa"
			if intent.Prehashed || len(intent.Context) != 0 {
				parameter = raw.EdDSAParams{Prehash: intent.Prehashed, Context: intent.Context}
			}
		case AlgorithmEd448:
			standard, alias = raw.CKM_EDDSA, "eddsa"
			parameter = raw.EdDSAParams{Prehash: intent.Prehashed, Context: intent.Context}
		case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87:
			if intent.ExternalMu {
				if intent.Hash != 0 || intent.Prehashed {
					return Route{}, fmt.Errorf("pkcs11: external mu cannot be combined with hash or prehash routing")
				}
				alias, aliasOnly = "ml-dsa-external-mu", true
				parameter = intent.MechanismParameter
			} else {
				var err error
				standard, alias, parameter, err = resolvePQCSignature(intent.Hash, intent.Prehashed, false, intent.Hedge, intent.Context)
				if err != nil {
					return Route{}, err
				}
			}
			if intent.Operation == OperationVerify {
				switch alias {
				case "ml-dsa-external-mu":
					alias = "ml-dsa-external-mu-verify"
				case "ml-dsa":
					alias = "ml-dsa-verify"
				case "hash-ml-dsa":
					alias = "hash-ml-dsa-verify"
				}
			}
		case AlgorithmSLHDSASHA2128S, AlgorithmSLHDSASHAKE128S, AlgorithmSLHDSASHA2128F, AlgorithmSLHDSASHAKE128F,
			AlgorithmSLHDSASHA2192S, AlgorithmSLHDSASHAKE192S, AlgorithmSLHDSASHA2192F, AlgorithmSLHDSASHAKE192F,
			AlgorithmSLHDSASHA2256S, AlgorithmSLHDSASHAKE256S, AlgorithmSLHDSASHA2256F, AlgorithmSLHDSASHAKE256F:
			var err error
			standard, alias, parameter, err = resolvePQCSignature(intent.Hash, intent.Prehashed, true, intent.Hedge, intent.Context)
			if err != nil {
				return Route{}, err
			}
		case AlgorithmHSS, AlgorithmLMS:
			if intent.Hash != 0 || intent.Prehashed || intent.ExternalMu {
				return Route{}, fmt.Errorf("pkcs11: %s signs messages directly; hash, prehash, and external-mu routing are not defined", intent.Algorithm)
			}
			standard = raw.CKM_HSS
			if intent.Algorithm == AlgorithmLMS {
				alias = "lms"
			} else {
				alias = "hss"
			}
			if intent.Operation == OperationVerify {
				alias += "-verify"
			}
		case AlgorithmXMSS:
			if intent.Hash != 0 || intent.Prehashed || intent.ExternalMu {
				return Route{}, fmt.Errorf("pkcs11: XMSS signs messages directly; hash, prehash, and external-mu routing are not defined")
			}
			standard, alias = raw.CKM_XMSS, "xmss"
			if intent.Operation == OperationVerify {
				alias = "xmss-verify"
			}
		case AlgorithmXMSSMT:
			if intent.Hash != 0 || intent.Prehashed || intent.ExternalMu {
				return Route{}, fmt.Errorf("pkcs11: XMSSMT signs messages directly; hash, prehash, and external-mu routing are not defined")
			}
			standard, alias = raw.CKM_XMSSMT, "xmssmt"
			if intent.Operation == OperationVerify {
				alias = "xmssmt-verify"
			}
		default:
			if len(spec.SignMechanisms) != 0 {
				standard, alias = spec.SignMechanisms[0], string(intent.Algorithm)
			} else if spec.SignAlias != "" {
				alias, aliasOnly = spec.SignAlias, true
			} else {
				return Route{}, fmt.Errorf("pkcs11: %s does not support signing", intent.Algorithm)
			}
		}
	case OperationEncapsulate:
		flag = raw.CKF_ENCAPSULATE
		if len(spec.KEMMechanisms) != 0 {
			standard, alias = spec.KEMMechanisms[0], "ml-kem-encapsulate"
		} else if spec.KEMAlias != "" {
			alias, aliasOnly = spec.KEMAlias, true
		} else {
			return Route{}, fmt.Errorf("pkcs11: %s is not a KEM", intent.Algorithm)
		}
	case OperationDecapsulate:
		flag = raw.CKF_DECAPSULATE
		if len(spec.KEMMechanisms) != 0 {
			standard, alias = spec.KEMMechanisms[0], "ml-kem-decapsulate"
		} else if spec.KEMAlias != "" {
			alias, aliasOnly = spec.KEMAlias, true
		} else {
			return Route{}, fmt.Errorf("pkcs11: %s is not a KEM", intent.Algorithm)
		}
	case OperationEncrypt, OperationDecrypt:
		flag = raw.CKF_ENCRYPT
		if intent.Operation == OperationDecrypt {
			flag = raw.CKF_DECRYPT
		}
		if intent.Algorithm == AlgorithmRSA {
			padding := intent.RSAPadding
			if padding == "" {
				padding = RSAPaddingOAEP
			}
			switch padding {
			case RSAPaddingOAEP:
				standard, alias = raw.CKM_RSA_PKCS_OAEP, "rsa-oaep"
				_, hashAlg, mgf, err := hashMechanisms(intent.Hash, false)
				if err != nil {
					return Route{}, err
				}
				parameter = raw.OAEPParams{HashAlg: hashAlg, MGF: mgf, Source: raw.CKZ_DATA_SPECIFIED, SourceData: intent.OAEPLabel}
			case RSAPaddingPKCS1v15:
				standard, alias = raw.CKM_RSA_PKCS, "rsa-pkcs"
			case RSAPaddingRaw:
				standard, alias = raw.CKM_RSA_X_509, "rsa-x509"
			default:
				return Route{}, fmt.Errorf("pkcs11: unsupported RSA encryption padding %q", padding)
			}
		} else if strings.HasPrefix(string(intent.Algorithm), "aes-") {
			switch intent.CipherMode {
			case "", CipherModeGCM:
				standard, alias = raw.CKM_AES_GCM, "aes-gcm"
				parameter = raw.GCMParams{IV: intent.IV, IVBits: uint(len(intent.IV) * 8), AAD: intent.AAD, TagBits: intent.TagBits}
			case CipherModeCBC:
				standard, alias = raw.CKM_AES_CBC_PAD, "aes-cbc-pad"
				parameter = intent.IV
			case CipherModeCTR:
				if len(intent.IV) != 16 {
					return Route{}, fmt.Errorf("pkcs11: AES-CTR counter must be 16 bytes")
				}
				var counter [16]byte
				copy(counter[:], intent.IV)
				standard, alias = raw.CKM_AES_CTR, "aes-ctr"
				parameter = raw.AESCTRParams{CounterBits: 128, Counter: counter}
			}
		} else {
			return Route{}, fmt.Errorf("pkcs11: encryption routing not defined for %s", intent.Algorithm)
		}
	default:
		return Route{}, fmt.Errorf("pkcs11: operation %q is not routed", intent.Operation)
	}

	if flag == 0 {
		switch intent.Operation {
		case OperationGenerate:
			if spec.KeyPair {
				flag = raw.CKF_GENERATE_KEY_PAIR
			} else {
				flag = raw.CKF_GENERATE
			}
		case OperationSign:
			flag = raw.CKF_SIGN
		case OperationVerify:
			flag = raw.CKF_VERIFY
		}
	}
	var selected uint
	var source string
	var reasons []string
	var selectionErr error
	if aliasOnly {
		selected, source, reasons, selectionErr = chooseVendorMechanism(device, alias, flag)
	} else {
		selected, source, reasons, selectionErr = chooseMechanism(device, standard, alias, flag)
	}
	if selectionErr == nil {
		if strings.HasPrefix(source, "vendor-adapter") {
			if hasKeyTypeAlias {
				route.KeyType = vendorKeyType
			}
			if hasParameterSetAlias {
				route.ParameterSet = vendorParameterSet
			}
		}
		route.Mechanism = raw.NewMechanism(selected, parameter)
		route.MechanismSource = source
		route.Reasons = append(route.Reasons, reasons...)
	}

	// Give only the selected module a chance to translate an advertised vendor
	// mechanism or provide a documented fallback when the standard route failed.
	adapted, adaptErr := adaptVendorRoute(device, route)
	if adaptErr != nil {
		return Route{}, adaptErr
	}
	route = adapted
	if route.Mechanism == nil {
		if selectionErr != nil {
			return Route{}, selectionErr
		}
		return Route{}, fmt.Errorf("pkcs11: vendor module returned no mechanism for %s %s", intent.Operation, intent.Algorithm)
	}
	route.buildTemplates(spec)
	return route, nil
}

// buildTemplates creates the minimum algorithm invariants. Storage policy,
// identity, usage flags, application TemplatePolicy, and vendor normalization
// are layered on later by the key-generation API.
func (r *Route) buildTemplates(spec algorithmSpec) {
	if r.Intent.Operation != OperationGenerate {
		return
	}
	if spec.KeyPair {
		r.PublicTemplate = []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY), raw.NewAttribute(raw.CKA_KEY_TYPE, r.KeyType)}
		r.PrivateTemplate = []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY), raw.NewAttribute(raw.CKA_KEY_TYPE, r.KeyType)}
		if len(spec.ECParams) > 0 {
			r.PublicTemplate = append(r.PublicTemplate, raw.NewAttribute(raw.CKA_EC_PARAMS, spec.ECParams))
		}
		if r.ParameterSet != 0 && !r.OmitParameterSetAttribute {
			r.PublicTemplate = append(r.PublicTemplate, raw.NewAttribute(raw.CKA_PARAMETER_SET, r.ParameterSet))
			r.PrivateTemplate = append(r.PrivateTemplate, raw.NewAttribute(raw.CKA_PARAMETER_SET, r.ParameterSet))
		}
		if r.Intent.Algorithm == AlgorithmRSA {
			r.PublicTemplate = append(r.PublicTemplate, raw.NewAttribute(raw.CKA_MODULUS_BITS, uint(3072)), raw.NewAttribute(raw.CKA_PUBLIC_EXPONENT, big.NewInt(65537)))
		}
	} else {
		r.SecretTemplate = []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY), raw.NewAttribute(raw.CKA_KEY_TYPE, r.KeyType), raw.NewAttribute(raw.CKA_VALUE_LEN, spec.SecretBytes)}
	}
}
