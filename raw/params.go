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
