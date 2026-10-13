package raw

import "unsafe"

// Mechanism is the Go form of CK_MECHANISM.
//
// Parameter may be nil, []byte, uint, one of the typed parameter structs in this
// package, a NativeParameterMarshaler, a ParameterMarshaler, or UnsafeParameter.
// The raw package copies managed parameter values into stable native memory.
// UnsafeParameter is the exception and remains caller-owned.
type Mechanism struct {
	// Mechanism is a CK_MECHANISM_TYPE value.
	Mechanism uint

	// Parameter is the mechanism-specific value described above.
	Parameter any
}

// NewMechanism constructs a mechanism and associates it with an optional
// mechanism-specific parameter value.
func NewMechanism(mechanism uint, parameter any) *Mechanism {
	return &Mechanism{Mechanism: mechanism, Parameter: parameter}
}

// ParameterMarshaler encodes a pointer-free custom mechanism parameter.
// The returned bytes are copied before the provider call. Pointer-bearing
// structures should use NativeParameterMarshaler instead.
type ParameterMarshaler interface {
	MarshalPKCS11Parameter() ([]byte, error)
}

// UnsafeParameter points at caller-owned native mechanism data.
// It bypasses the raw package's layout, allocation, and lifetime handling. The
// memory must remain valid for the whole operation, including multipart work.
type UnsafeParameter struct {
	// Pointer is the address of the native mechanism-parameter structure.
	Pointer unsafe.Pointer

	// Length is the structure size supplied as CK_MECHANISM.ulParameterLen.
	Length uint
}

// PSSParams describes CK_RSA_PKCS_PSS_PARAMS for RSA-PSS signing and
// verification mechanisms.
type PSSParams struct {
	// HashAlg is the digest mechanism, for example CKM_SHA256.
	HashAlg uint

	// MGF identifies the mask-generation function, for example CKG_MGF1_SHA256.
	MGF uint

	// SaltLen is the salt length in bytes.
	SaltLen uint
}

// OAEPParams describes CK_RSA_PKCS_OAEP_PARAMS for RSA-OAEP encryption,
// decryption, wrapping, and unwrapping operations.
type OAEPParams struct {
	// HashAlg is the digest mechanism used by OAEP.
	HashAlg uint

	// MGF identifies the mask-generation function used by OAEP.
	MGF uint

	// Source identifies how SourceData is interpreted, normally CKZ_DATA_SPECIFIED.
	Source uint

	// SourceData is the optional OAEP label. It is copied into backend-owned
	// native-call memory together with the containing parameter structure.
	SourceData []byte
}

// AESCTRParams describes CK_AES_CTR_PARAMS.
type AESCTRParams struct {
	// CounterBits is the number of low-order bits in Counter that are incremented
	// for each block.
	CounterBits uint

	// Counter is the complete 128-bit initial counter block.
	Counter [16]byte
}

// GCMParams describes CK_GCM_PARAMS for AES-GCM and compatible mechanisms.
type GCMParams struct {
	// IV is the initialization vector. Its bytes are copied into stable native
	// memory owned by the current call or retained operation.
	IV []byte

	// IVBits is the significant IV length in bits. A zero value allows the
	// marshaler to derive the value from len(IV) where supported.
	IVBits uint

	// AAD is additional authenticated data. It is authenticated but not encrypted.
	AAD []byte

	// TagBits is the requested authentication-tag length in bits.
	TagBits uint
}

// ChaCha20Params describes CK_CHACHA20_PARAMS for CKM_CHACHA20.
type ChaCha20Params struct {
	// BlockCounter is the initial block counter, normally 4 bytes. RFC 8439
	// places it ahead of the nonce in the 16-byte IV.
	BlockCounter []byte

	// BlockCounterBits is the significant counter length in bits. Zero derives
	// the value as 8*len(BlockCounter), which is the 32 bits tokens expect.
	BlockCounterBits uint

	// Nonce is the nonce, normally 12 bytes.
	Nonce []byte

	// NonceBits is the significant nonce length in bits. Zero derives the value
	// as 8*len(Nonce), which is the 96 bits tokens expect.
	NonceBits uint
}

// ChaCha20Poly1305Params describes CK_SALSA20_CHACHA20_POLY1305_PARAMS for the
// single-part ChaCha20-Poly1305 AEAD mechanism. The authentication tag is
// always 128 bits and is appended to the ciphertext.
type ChaCha20Poly1305Params struct {
	// Nonce is the 12-byte nonce.
	Nonce []byte

	// AAD is authenticated but not encrypted.
	AAD []byte
}

// ChaCha20Poly1305MsgParams describes
// CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, which EncryptMessage,
// EncryptMessageBegin, and EncryptMessageNext take as their per-message
// parameter for CKM_CHACHA20_POLY1305 (the decrypt side likewise). The
// 16-byte tag lands in Tag after encryption.
type ChaCha20Poly1305MsgParams struct {
	// Nonce is the 12-byte nonce.
	Nonce []byte

	// Tag is the 16-byte authentication tag. It is an output for encryption and
	// an input for decryption.
	Tag []byte
}

// GCMMessageParams describes CK_GCM_MESSAGE_PARAMS, the per-message parameter
// for EncryptMessage/DecryptMessage (and their Begin/Next forms) under
// CKM_AES_GCM. EncryptMessage writes the tag into Tag when the parameter is a
// pointer to this type.
type GCMMessageParams struct {
	// IV is the complete nonce.
	IV []byte

	// IVFixedBits is the significant IV length in bits. Zero derives the value
	// as 8*len(IV).
	IVFixedBits uint

	// IVGenerator is a CK_GENERATOR_FUNCTION value, normally CKG_NO_GENERATE
	// when the caller supplies IV.
	IVGenerator uint

	// Tag is the authentication tag buffer. It is an output for encryption and
	// an input for decryption.
	Tag []byte

	// TagBits is the requested tag length in bits. Zero and 128 both allocate a
	// 16-byte buffer, which is the maximum AES-GCM produces.
	TagBits uint
}

// HKDFParams describes CK_HKDF_PARAMS for CKM_HKDF_DERIVE and CKM_HKDF_DATA.
type HKDFParams struct {
	// Extract and Expand select the RFC 5869 stages. CKM_HKDF_DERIVE performs
	// the combined extract-and-expand derivation when both are true.
	Extract bool
	Expand  bool

	// PRFHashMechanism is the digest mechanism used inside HMAC, for example
	// CKM_SHA256.
	PRFHashMechanism uint

	// SaltType is a CKF_HKDF_SALT_* value that selects how the salt is supplied.
	SaltType uint

	// Salt is the salt bytes used when SaltType is CKF_HKDF_SALT_DATA.
	Salt []byte

	// SaltKey is the handle of a key object supplying the salt when SaltType is
	// CKF_HKDF_SALT_KEY.
	SaltKey ObjectHandle

	// Info is the RFC 5869 context string used by the expand stage.
	Info []byte
}

// IKEPRFDeriveParams describes CK_IKE_PRF_DERIVE_PARAMS for CKM_IKE_PRF_DERIVE.
type IKEPRFDeriveParams struct {
	// PRFMechanism is an HMAC mechanism such as CKM_SHA256_HMAC.
	PRFMechanism uint

	// DataAsKey derives a new key directly from Ni and Nr. It is mutually
	// exclusive with Rekey.
	DataAsKey bool

	// Rekey updates the existing key object NewKey instead of producing a new
	// key from Ni and Nr.
	Rekey bool

	// Ni is the initiator nonce, at least 16 bytes.
	Ni []byte

	// Nr is the responder nonce, at least 16 bytes.
	Nr []byte

	// NewKey is the handle of the key object updated when Rekey is true.
	NewKey ObjectHandle
}

// IKE1PRFDerivParams describes CK_IKE1_PRF_DERIVE_PARAMS for
// CKM_IKE1_PRF_DERIVE.
type IKE1PRFDerivParams struct {
	// PRFMechanism is an HMAC mechanism such as CKM_SHA256_HMAC.
	PRFMechanism uint

	// HasPrevKey states whether PrevKey names a usable key object.
	HasPrevKey bool

	// KeyGxy is the handle of the key holding g^xy.
	KeyGxy ObjectHandle

	// PrevKey is the handle of the previous key when HasPrevKey is true.
	PrevKey ObjectHandle

	// CKYi is the initiator cookie.
	CKYi []byte

	// CKYr is the responder cookie.
	CKYr []byte

	// KeyNumber selects the derived key index.
	KeyNumber byte
}

// IKE1ExtendedDeriveParams describes CK_IKE1_EXTENDED_DERIVE_PARAMS for
// CKM_IKE1_EXTENDED_DERIVE.
type IKE1ExtendedDeriveParams struct {
	// PRFMechanism is an HMAC mechanism such as CKM_SHA256_HMAC.
	PRFMechanism uint

	// HasKeyGxy states whether KeyGxy names a usable key object.
	HasKeyGxy bool

	// KeyGxy is the handle of the key holding g^xy.
	KeyGxy ObjectHandle

	// ExtraData is additional data mixed into the derivation.
	ExtraData []byte
}

// IKE2PRFPlusDeriveParams describes CK_IKE2_PRF_PLUS_DERIVE_PARAMS for
// CKM_IKE2_PRF_PLUS_DERIVE.
type IKE2PRFPlusDeriveParams struct {
	// PRFMechanism is an HMAC mechanism such as CKM_SHA256_HMAC.
	PRFMechanism uint

	// HasSeedKey states whether SeedKey names a usable key object.
	HasSeedKey bool

	// SeedKey is the handle of an optional seed key object.
	SeedKey ObjectHandle

	// SeedData is additional seed material mixed into the derivation.
	SeedData []byte
}

// ECDH1DeriveParams describes CK_ECDH1_DERIVE_PARAMS for ECDH key derivation.
type ECDH1DeriveParams struct {
	// KDF identifies the post-processing KDF, or CKD_NULL when the raw shared
	// secret should be used directly.
	KDF uint

	// SharedData is optional shared information consumed by the selected KDF.
	SharedData []byte

	// PublicData contains the peer public point in the encoding required by the
	// selected mechanism and token.
	PublicData []byte
}

// EdDSAParams describes CK_EDDSA_PARAMS.
type EdDSAParams struct {
	// Prehash selects the prehash EdDSA variant rather than the pure variant.
	Prehash bool

	// Context contains the optional domain-separation context.
	Context []byte
}

// HedgeMode controls whether a post-quantum signature operation requests
// randomized hedging or deterministic signing.
type HedgeMode uint

const (
	// HedgePreferred allows hedged signing when randomness is available, while
	// permitting the token to fall back to deterministic signing.
	HedgePreferred HedgeMode = HedgeMode(CKH_HEDGE_PREFERRED)

	// HedgeRequired requires the token to use hedged signing.
	HedgeRequired HedgeMode = HedgeMode(CKH_HEDGE_REQUIRED)

	// DeterministicOnly requires deterministic signing and disallows hedging.
	DeterministicOnly HedgeMode = HedgeMode(CKH_DETERMINISTIC_REQUIRED)
)

// SignAdditionalContext describes CK_SIGN_ADDITIONAL_CONTEXT for signature
// mechanisms that accept hedging and domain-separation context directly.
type SignAdditionalContext struct {
	// Hedge selects the requested hedging behavior.
	Hedge HedgeMode

	// Context is the application-provided domain-separation context.
	Context []byte
}

// HashSignAdditionalContext describes CK_HASH_SIGN_ADDITIONAL_CONTEXT for
// prehash signature mechanisms that additionally identify the external hash.
type HashSignAdditionalContext struct {
	// Hedge selects the requested hedging behavior.
	Hedge HedgeMode

	// Context is the application-provided domain-separation context.
	Context []byte

	// Hash identifies the mechanism used to produce the externally supplied digest.
	Hash uint
}

// KeyDerivationStringData describes CK_KEY_DERIVATION_STRING_DATA, the raw
// data parameter for CKM_CONCATENATE_BASE_AND_DATA, CKM_CONCATENATE_DATA_AND_BASE,
// and CKM_XOR_BASE_AND_DATA.
type KeyDerivationStringData struct {
	// Data is concatenated with or XORed into the base key value depending on
	// the mechanism. XOR applies the base key cyclically to Data.
	Data []byte
}

// AESCBCEncryptDataParams describes CK_AES_CBC_ENCRYPT_DATA_PARAMS for
// CKM_AES_CBC_ENCRYPT_DATA. The mechanism derives a key by AES-CBC encrypting
// Data under the base key and truncating to the requested CKA_VALUE_LEN.
type AESCBCEncryptDataParams struct {
	// IV is the 16-byte CBC initialization vector.
	IV [16]byte

	// Data is the plaintext encrypted by the derivation. It must be a multiple
	// of the AES block size.
	Data []byte
}

// RSAAESKeyWrapParams describes CK_RSA_AES_KEY_WRAP_PARAMS for
// CKM_RSA_AES_KEY_WRAP. The mechanism wraps the target with a fresh AES key and
// RSA-OAEP encrypts that key under the wrapping RSA public key.
type RSAAESKeyWrapParams struct {
	// AESKeyBits selects the size of the ephemeral AES wrapping key.
	AESKeyBits uint

	// OAEPParams selects the RSA-OAEP encoding applied to the ephemeral key.
	// Nil requests the token's default OAEP parameters.
	OAEPParams *OAEPParams
}

// CCMParams describes CK_CCM_PARAMS for the single-part CKM_AES_CCM mechanism.
// The ciphertext output has MACLen tag bytes appended.
type CCMParams struct {
	// DataLen is the complete plaintext or ciphertext length in bytes.
	DataLen uint

	// Nonce is 7 to 13 bytes long.
	Nonce []byte

	// AAD is authenticated but not encrypted.
	AAD []byte

	// MACLen is the authentication tag length in bytes (4 to 16, even).
	MACLen uint
}

// CCMMessageParams describes CK_CCM_MESSAGE_PARAMS, the per-message parameter
// taken by EncryptMessage/DecryptMessage under CKM_AES_CCM. The AAD is supplied
// as the per-message associated-data argument rather than inside this struct.
type CCMMessageParams struct {
	// DataLen is the complete plaintext or ciphertext length in bytes.
	DataLen uint

	// Nonce is 7 to 13 bytes long.
	Nonce []byte

	// NonceFixedBits is the significant nonce length in bits. Zero derives the
	// value as 8*len(Nonce).
	NonceFixedBits uint

	// NonceGenerator is a CK_GENERATOR_FUNCTION value, normally CKG_NO_GENERATE
	// when the caller supplies the nonce.
	NonceGenerator uint

	// MAC is the authentication tag. It is an output for encryption and an
	// input for decryption. MACLen sets the tag length in bytes; zero selects
	// the provider default up to 16 bytes.
	MAC    []byte
	MACLen uint
}

// GCMWrapParams describes CK_GCM_WRAP_PARAMS for C_WrapKeyAuthenticated under
// CKM_AES_GCM.
type GCMWrapParams struct {
	// IV is the wrapping IV.
	IV []byte

	// IVFixedBits is the significant IV length in bits. Zero derives the value
	// as 8*len(IV).
	IVFixedBits uint

	// IVGenerator is a CK_GENERATOR_FUNCTION value.
	IVGenerator uint

	// AAD is authenticated alongside the wrapped key.
	AAD []byte

	// TagBits is the requested tag length in bits.
	TagBits uint
}

// CCMWrapParams describes CK_CCM_WRAP_PARAMS for C_WrapKeyAuthenticated under
// CKM_AES_CCM.
type CCMWrapParams struct {
	// DataLen is the wrapped-key length in bytes.
	DataLen uint

	// Nonce is 7 to 13 bytes long.
	Nonce []byte

	// NonceFixedBits is the significant nonce length in bits. Zero derives the
	// value as 8*len(Nonce).
	NonceFixedBits uint

	// NonceGenerator is a CK_GENERATOR_FUNCTION value.
	NonceGenerator uint

	// AAD is authenticated alongside the wrapped key.
	AAD []byte

	// MACLen is the tag length in bytes (4 to 16, even).
	MACLen uint
}

// PBKDF2Params describes CK_PKCS5_PBKD2_PARAMS2 for CKM_PKCS5_PBKD2 key
// generation and derivation. The password is supplied directly in the
// parameter; the derived result lands in the generated or derived key object.
type PBKDF2Params struct {
	// SaltSource is a CKZ_SALT_* value, normally CKZ_SALT_SPECIFIED.
	SaltSource uint

	// Salt is the PBKDF2 salt bytes.
	Salt []byte

	// Iterations is the PBKDF2 iteration count.
	Iterations uint

	// PRF is a CKP_PKCS5_PBKD2_HMAC_* pseudorandom-function selector.
	PRF uint

	// PRFData carries optional PRF-specific parameters. Providers that support
	// only HMAC PRFs reject non-empty data.
	PRFData []byte

	// Password is the PBKDF2 password supplied through the mechanism parameter.
	Password []byte
}

// OTPParam is one CK_OTP_PARAM entry inside OTPParams.
type OTPParam struct {
	// Type is a CK_OTP_* selector such as CK_OTP_VALUE or CK_OTP_COUNTER.
	Type uint

	// Value is the parameter payload.
	Value []byte
}

// OTPParams describes CK_OTP_PARAMS, the optional parameter for CKM_HOTP and
// related OTP mechanisms. Entries can override the key's stored counter,
// request an output format, or select an output length.
type OTPParams struct {
	// Params is the ordered CK_OTP_PARAM array.
	Params []OTPParam
}

// OTPSignatureInfo reports the decoded contents of a CK_OTP_SIGNATURE_INFO
// blob returned by C_Sign under CKM_HOTP.
type OTPSignatureInfo struct {
	// Params contains the parameter entries embedded in the signature blob.
	Params []OTPParam
}

// SP800108CounterFormat describes CK_SP800_108_COUNTER_FORMAT.
type SP800108CounterFormat struct {
	// LittleEndian selects the counter byte order.
	LittleEndian bool

	// WidthInBits is the counter width: 8, 16, 24, or 32.
	WidthInBits uint
}

// SP800108DKMLengthFormat describes CK_SP800_108_DKM_LENGTH_FORMAT, which
// encodes how the derived-key-material length appears in the PRF input.
type SP800108DKMLengthFormat struct {
	// Method is a CK_SP800_108_DKM_LENGTH_* selector.
	Method uint

	// LittleEndian selects the length byte order.
	LittleEndian bool

	// WidthInBits is the encoded length width: 8, 16, 24, 32, or 64.
	WidthInBits uint
}

// SP800108DataParam is the Go form of one CK_PRF_DATA_PARAM entry. Type is a
// CK_SP800_108_* selector and Value is interpreted by type:
// CK_SP800_108_ITERATION_VARIABLE takes SP800108CounterFormat, CK_SP800_108_DKM_LENGTH
// takes SP800108DKMLengthFormat, and byte-array or key-handle entries take
// []byte or ObjectHandle respectively.
type SP800108DataParam struct {
	Type  uint
	Value any
}

// SP800108DerivedKey describes one CK_DERIVED_KEY output entry.
type SP800108DerivedKey struct {
	// Template is the attribute template applied to the derived key.
	Template []*Attribute

	// Key receives the derived key handle after the derive call completes.
	Key *ObjectHandle
}

// SP800108KDFParams describes CK_SP800_108_KDF_PARAMS for
// CKM_SP800_108_COUNTER_KDF.
type SP800108KDFParams struct {
	// PRFType selects the inner PRF mechanism, for example CKM_SHA256_HMAC or
	// CKM_AES_CMAC.
	PRFType uint

	// DataParams is the CK_PRF_DATA_PARAM array describing counter, label,
	// context, and length encodings.
	DataParams []SP800108DataParam

	// AdditionalDerivedKeys requests extra output keys beyond the primary
	// C_DeriveKey result.
	AdditionalDerivedKeys []SP800108DerivedKey
}

// SP800108FeedbackKDFParams describes CK_SP800_108_FEEDBACK_KDF_PARAMS for
// CKM_SP800_108_FEEDBACK_KDF.
type SP800108FeedbackKDFParams struct {
	// PRFType selects the inner PRF mechanism.
	PRFType uint

	// DataParams is the CK_PRF_DATA_PARAM array.
	DataParams []SP800108DataParam

	// IV is the feedback initialization vector.
	IV []byte

	// AdditionalDerivedKeys requests extra output keys.
	AdditionalDerivedKeys []SP800108DerivedKey
}

// TLS12MasterKeyDeriveParams describes CK_TLS12_MASTER_KEY_DERIVE_PARAMS for
// CKM_TLS12_MASTER_KEY_DERIVE.
type TLS12MasterKeyDeriveParams struct {
	// ClientRandom and ServerRandom are the 32-byte TLS handshake randoms.
	ClientRandom []byte
	ServerRandom []byte

	// Version optionally receives the negotiated TLS version. Leave nil for
	// DH-style suites where the version is not embedded in the pre-master key.
	Version *Version

	// PRFHashMechanism is the digest mechanism selecting the TLS PRF hash,
	// for example CKM_SHA256.
	PRFHashMechanism uint
}

// TLS12ExtendedMasterKeyDeriveParams describes
// CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS for
// CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE.
type TLS12ExtendedMasterKeyDeriveParams struct {
	// SessionHash is the TLS session hash input.
	SessionHash []byte

	// Version optionally receives the negotiated TLS version.
	Version *Version

	// PRFHashMechanism is the digest mechanism selecting the TLS PRF hash.
	PRFHashMechanism uint
}

// TLS12KeyMaterial collects the object handles and IVs written into
// CK_SSL3_KEY_MAT_OUT / CK_TLS12_KEY_MAT_OUT by a key-material derivation.
type TLS12KeyMaterial struct {
	// ClientMACSecret, ServerMACSecret, ClientKey, and ServerKey receive the
	// handles of objects created by the derivation.
	ClientMACSecret ObjectHandle
	ServerMACSecret ObjectHandle
	ClientKey       ObjectHandle
	ServerKey       ObjectHandle

	// IVClient and IVServer receive the generated initialization vectors when
	// the derivation allocates them.
	IVClient []byte
	IVServer []byte
}

// TLS12KeyMatParams describes CK_TLS12_KEY_MAT_PARAMS for
// CKM_TLS12_KEY_AND_MAC_DERIVE and CKM_TLS12_KEY_SAFE_DERIVE.
type TLS12KeyMatParams struct {
	// MACSizeBits and KeySizeBits are the produced MAC and cipher-key widths.
	MACSizeBits uint
	KeySizeBits uint

	// IVSizeBits is the requested IV width. Zero lets the token omit IV
	// material.
	IVSizeBits uint

	// IsExport selects the exportable TLS cipher variant.
	IsExport bool

	// ClientRandom and ServerRandom are the 32-byte TLS handshake randoms.
	ClientRandom []byte
	ServerRandom []byte

	// KeyMaterial receives the derived object handles and IVs after the call.
	KeyMaterial *TLS12KeyMaterial

	// PRFHashMechanism is the digest mechanism selecting the TLS PRF hash.
	PRFHashMechanism uint
}

// TLSKDFParams describes CK_TLS_KDF_PARAMS for CKM_TLS_KDF and CKM_TLS12_KDF.
type TLSKDFParams struct {
	// PRFMechanism is the digest mechanism selecting the TLS PRF hash.
	PRFMechanism uint

	// Label is the TLS KDF label bytes and must be non-empty.
	Label []byte

	// ClientRandom and ServerRandom are the 32-byte TLS handshake randoms.
	ClientRandom []byte
	ServerRandom []byte

	// ContextData is the optional TLS 1.3 context string.
	ContextData []byte
}

// TLSMACParams describes CK_TLS_MAC_PARAMS for CKM_TLS_MAC and CKM_TLS12_MAC,
// which compute the TLS finished-message MAC over supplied data.
type TLSMACParams struct {
	// PRFHashMechanism is the digest mechanism selecting the TLS PRF hash.
	PRFHashMechanism uint

	// MACLength is the requested MAC length in bytes.
	MACLength uint

	// ServerOrClient selects the finished-message label: 1 for
	// "server finished", 2 for "client finished".
	ServerOrClient uint
}

// DSAParameterGenParams describes CK_DSA_PARAMETER_GEN_PARAM for
// CKM_DSA_PARAMETER_GEN, which creates a CKO_DOMAIN_PARAMETERS object holding
// freshly generated DSA domain parameters.
type DSAParameterGenParams struct {
	// Hash is the digest mechanism used in the generation proof, for example
	// CKM_SHA256.
	Hash uint

	// Seed optionally carries caller-chosen generation seed bytes.
	Seed []byte

	// Index selects the counter value embedded in verifiable generation.
	Index uint
}
