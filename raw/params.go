package raw

import "unsafe"

// Mechanism is the Go representation of CK_MECHANISM.
//
// Mechanism identifies the PKCS #11 operation to perform, such as CKM_RSA_PKCS,
// CKM_AES_GCM, or CKM_ECDH1_DERIVE. Parameter contains the mechanism-specific
// input that will be converted into the corresponding native ABI
// representation before the provider call is made.
//
// Supported parameter forms are:
//   - nil, for mechanisms that do not take parameters;
//   - []byte, for mechanisms whose parameter is an opaque byte string;
//   - uint, for mechanisms whose parameter is a CK_ULONG value;
//   - one of the typed parameter structures declared in this file;
//   - NativeParameterMarshaler, for pointer-bearing caller/vendor structures;
//   - ParameterMarshaler, for pointer-free caller/vendor structures; or
//   - UnsafeParameter, for an already allocated native structure.
//
// Parameter values converted by the raw package are copied into stable
// backend-owned memory. The caller may therefore release or reuse its input
// after the method returns; when a multipart operation retains a mechanism,
// the raw package retains its own complete native copy until the operation
// completes. UnsafeParameter is the exception because its lifetime remains the
// caller's responsibility.
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

// ParameterMarshaler converts a caller-defined PKCS #11 mechanism parameter
// into its exact native byte representation.
//
// This is primarily useful for pointer-free vendor-defined mechanisms whose
// parameter structures are not represented by one of the standard types below. The
// returned bytes are copied into backend-owned native-call memory before the
// module is called, so the returned slice does not need to remain valid
// afterward.
//
// The encoded structure must not contain live pointers. Pointer-bearing
// structures require dedicated marshaling so that each referenced buffer is
// separately allocated and kept alive for the complete native operation.
type ParameterMarshaler interface {
	MarshalPKCS11Parameter() ([]byte, error)
}

// UnsafeParameter supplies a mechanism parameter that is already laid out in
// native memory.
//
// This bypasses all type checking, allocation, endian conversion, alignment
// handling, and lifetime management normally performed by the raw package. It
// should be reserved for vendor structures that cannot be expressed through a
// typed parameter or ParameterMarshaler.
//
// Pointer must reference at least Length bytes in native-accessible memory and
// must remain valid and unchanged for the entire native operation. For multipart operations, that
// may extend beyond the initialization call until the operation is completed,
// cancelled, or its session is closed.
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
