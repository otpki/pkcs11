package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha512"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/otpki/pkcs11/raw"
)

// OpaquePublicKey represents algorithms not modeled by Go's standard crypto
// package (for example ML-DSA, ML-KEM, SLH-DSA, HSS, XMSS, XMSSMT, and Ed448).
// Encoding contains the provider's public-key representation. For standardized
// algorithms this is normally the bytes exposed by CKA_PUBLIC_KEY_INFO,
// CKA_VALUE, or the provider's documented equivalent.
type OpaquePublicKey struct {
	// Algorithm identifies how Encoding should be interpreted.
	Algorithm Algorithm
	// Encoding is an independent copy of the provider's public representation.
	// The exact format is algorithm- and sometimes vendor-specific.
	Encoding []byte
}

// SignatureOptions describes one signing or verification operation without
// exposing a vendor mechanism number in the common case. The same value can be
// passed to Client.Sign, Client.Verify, Signer.SignContext, or crypto.Signer's
// Sign method.
//
// Input interpretation is explicit:
//   - Prehashed=false means data is the complete message.
//   - Prehashed=true means data is a digest produced by Hash.
//   - ExternalMu=true means data is the 64-byte ML-DSA mu value.
//
// MechanismOverride and MechanismParameter are expert escape hatches. Leaving
// them unset allows the driver to prefer a standard PKCS #11 3.2 mechanism and
// transparently use a detected vendor route only when necessary.
type SignatureOptions struct {
	// Algorithm defaults to the algorithm recorded on the key or Signer.
	Algorithm Algorithm
	// Hash selects a combined hash-and-sign mechanism or identifies a supplied digest.
	Hash crypto.Hash
	// Prehashed states that the input is the digest named by Hash.
	Prehashed bool
	// RSAPadding selects PKCS #1 v1.5, PSS, or the raw RSA primitive.
	RSAPadding RSAPadding
	// PSSSaltLength is the explicit salt length in bytes. Zero selects the
	// high-level default appropriate to the calling API.
	PSSSaltLength int
	// Context is the EdDSA or standardized PQC domain-separation context.
	Context []byte
	// Hedge controls randomized versus deterministic standardized PQC signing.
	Hedge HedgeMode
	// ExternalMu interprets the input as the 64-byte ML-DSA mu value and selects
	// a vendor extension when the detected adapter exposes one.
	ExternalMu bool

	// MechanismOverride bypasses standard-first routing.
	MechanismOverride *uint
	// MechanismParameter replaces the parameter synthesized by the router.
	MechanismParameter any
}

// HashFunc implements crypto.SignerOpts. A zero value is valid for algorithms
// that sign complete messages, including direct ML-DSA and Ed25519.
func (o SignatureOptions) HashFunc() crypto.Hash { return o.Hash }

// SignerConfig binds an existing key pair and default signing policy to a Signer.
type SignerConfig struct {
	// Private identifies the private key. A durable CKA_ID is preferred so the
	// signer can recover after a session, connection, or object-handle change.
	Private ObjectRef
	// Public optionally identifies the matching public key. When omitted, the
	// driver resolves it from Private's CKA_ID, unique ID, or label.
	Public ObjectRef
	// Algorithm defaults to Private.Algorithm.
	Algorithm Algorithm
	// DefaultHash is used when Sign receives an option whose HashFunc is zero.
	DefaultHash crypto.Hash
	// DefaultPadding applies to RSA. The zero value selects RSA-PSS for explicit
	// SignatureOptions and PKCS #1 v1.5 for ordinary crypto.Signer options.
	DefaultPadding RSAPadding
	// Context and Hedge are defaults for direct PQC signatures.
	Context []byte
	Hedge   HedgeMode
}

// Signer implements crypto.Signer using a managed token-resident private key.
// It is safe for concurrent use: each operation resolves the object in a fresh
// managed session and does not retain multipart PKCS #11 state on the Signer.
type Signer struct {
	client      *Client
	private     ObjectRef
	public      ObjectRef
	algorithm   Algorithm
	publicKey   crypto.PublicKey
	defaultHash crypto.Hash
	padding     RSAPadding
	context     []byte
	hedge       HedgeMode
}

func newSigner(ctx context.Context, client *Client, config SignerConfig) (*Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("pkcs11: signer client is required")
	}
	algorithm := config.Algorithm
	if algorithm == "" {
		algorithm = config.Private.Algorithm
	}
	if algorithm == "" {
		return nil, fmt.Errorf("pkcs11: signer algorithm is required")
	}
	public := config.Public
	if public.Handle == 0 && public.ID == nil && public.Label == "" && public.UniqueID == "" {
		// Reuse the private object's durable locator while changing only the class;
		// resolveObject will find the current-session public handle later.
		public = config.Private
		public.Class = raw.CKO_PUBLIC_KEY
	}
	public.Algorithm = algorithm
	publicKey, err := client.loadPublicKey(ctx, public, algorithm)
	if err != nil {
		return nil, err
	}
	padding := config.DefaultPadding
	if padding == "" {
		padding = RSAPaddingPSS
	}
	return &Signer{client: client, private: config.Private, public: public, algorithm: algorithm, publicKey: publicKey, defaultHash: config.DefaultHash, padding: padding, context: append([]byte(nil), config.Context...), hedge: config.Hedge}, nil
}

// Public returns the public key corresponding to the token-resident private key.
func (s *Signer) Public() crypto.PublicKey { return s.publicKey }

// Sign implements crypto.Signer. The crypto.Signer interface has no context,
// so this method uses context.Background. Call SignContext when cancellation or
// an operation deadline matters. random is accepted for interface compatibility;
// randomness used by an HSM signature mechanism is generated by the provider.
func (s *Signer) Sign(_ io.Reader, input []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(context.Background(), input, opts)
}

// SignContext performs the same operation as Sign while honoring ctx for
// session acquisition, retries, login, and recovery.
func (s *Signer) SignContext(ctx context.Context, input []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signInput(ctx, input, opts, false)
}

// SignMessage implements crypto.MessageSigner. Unlike Sign it always receives
// the complete message: hash-based algorithms are routed through the combined
// hash-and-sign mechanisms so the token performs the hashing, and the result
// is identical to Sign on the corresponding digest. When the token does not
// expose a combined mechanism, the message is hashed in software and signed
// through the raw or externally prehashed mechanism instead. Ed25519 honors
// *ed25519.Options Context and Hash for the ctx/ph variants.
func (s *Signer) SignMessage(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignMessageContext(context.Background(), message, opts)
}

// SignMessageContext performs the same operation as SignMessage while honoring
// ctx for session acquisition, retries, login, and recovery.
func (s *Signer) SignMessageContext(ctx context.Context, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signInput(ctx, message, opts, true)
}

// signInput is the shared signing path. messageLevel selects the input
// convention: false means the crypto.Signer digest contract, true means the
// crypto.MessageSigner complete-message contract.
func (s *Signer) signInput(ctx context.Context, input []byte, opts crypto.SignerOpts, messageLevel bool) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("pkcs11: signer is nil or closed")
	}
	intent, err := s.signIntent(input, opts, messageLevel)
	if err != nil {
		return nil, err
	}
	signature, err := s.client.sign(ctx, s.private, intent, input)
	if err == nil || !messageLevel {
		return signature, err
	}
	fallback, hash, ok := s.messageDigestFallback(intent)
	if !ok {
		return nil, err
	}
	if _, resolveErr := s.client.Resolve(fallback); resolveErr != nil {
		return nil, err
	}
	hasher := hash.New()
	_, _ = hasher.Write(input)
	return s.client.sign(ctx, s.private, fallback, hasher.Sum(nil))
}

// messageDigestFallback converts a message-level intent into the equivalent
// digest-level intent for tokens that cannot hash internally: hashing the
// message in software and signing through the raw or externally prehashed
// mechanism produces an identical signature. It reports false when the
// algorithm has no digest form or the caller dictated the input shape or the
// mechanism explicitly.
func (s *Signer) messageDigestFallback(intent Intent) (Intent, crypto.Hash, bool) {
	if intent.Prehashed || intent.ExternalMu || intent.MechanismOverride != nil || intent.MechanismParameter != nil {
		return Intent{}, 0, false
	}
	switch s.algorithm {
	case AlgorithmRSA, AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521,
		AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87,
		AlgorithmSLHDSASHA2128S, AlgorithmSLHDSASHAKE128S, AlgorithmSLHDSASHA2128F, AlgorithmSLHDSASHAKE128F,
		AlgorithmSLHDSASHA2192S, AlgorithmSLHDSASHAKE192S, AlgorithmSLHDSASHA2192F, AlgorithmSLHDSASHAKE192F,
		AlgorithmSLHDSASHA2256S, AlgorithmSLHDSASHAKE256S, AlgorithmSLHDSASHA2256F, AlgorithmSLHDSASHAKE256F:
	default:
		return Intent{}, 0, false
	}
	hash := intent.Hash
	if hash == 0 {
		hash = defaultSignatureHash(s.algorithm)
	}
	if hash == 0 || !hash.Available() {
		return Intent{}, 0, false
	}
	intent.Prehashed = true
	intent.Hash = hash
	return intent, hash, true
}

// signIntent resolves opts and the configured signer defaults into a route
// intent. messageLevel mirrors signInput: when true, input is always the
// complete message, so hash-based algorithms are pointed at the combined
// hash-and-sign mechanisms instead of digest input.
func (s *Signer) signIntent(input []byte, opts crypto.SignerOpts, messageLevel bool) (Intent, error) {
	hash := crypto.Hash(0)
	if opts != nil {
		hash = opts.HashFunc()
	}
	if hash == 0 {
		hash = s.defaultHash
	}
	if messageLevel && hash == 0 {
		hash = defaultSignatureHash(s.algorithm)
	}
	intent := Intent{Operation: OperationSign, Algorithm: s.algorithm, Hash: hash, Context: s.context, Hedge: s.hedge}
	if custom, ok := signatureOptions(opts); ok {
		// SignatureOptions is the explicit driver contract and therefore replaces
		// Signer defaults field by field rather than being interpreted as a generic
		// crypto.SignerOpts hash-only value.
		if custom.Algorithm != "" && custom.Algorithm != s.algorithm {
			return Intent{}, fmt.Errorf("pkcs11: signer algorithm %q does not match requested %q", s.algorithm, custom.Algorithm)
		}
		intent.Hash = custom.Hash
		intent.Prehashed = custom.Prehashed
		intent.RSAPadding = custom.RSAPadding
		intent.PSSSaltLength = custom.PSSSaltLength
		intent.Context = append([]byte(nil), custom.Context...)
		intent.Hedge = custom.Hedge
		intent.ExternalMu = custom.ExternalMu
		intent.MechanismOverride = custom.MechanismOverride
		intent.MechanismParameter = custom.MechanismParameter
		if messageLevel && intent.Prehashed {
			switch s.algorithm {
			case AlgorithmEd25519, AlgorithmEd448:
				// EdDSA has no digest-input form: its Prehash flag selects the
				// ph variant, and the token still receives the whole message.
			default:
				// Elsewhere Prehashed describes the input shape. SignMessage
				// input is always the complete message, so a requested prehash
				// becomes the token-internal hash variant selected by Hash.
				intent.Prehashed = false
			}
		}
	}
	switch s.algorithm {
	case AlgorithmRSA:
		if _, custom := signatureOptions(opts); !custom {
			intent.Prehashed = !messageLevel
			intent.RSAPadding = s.padding
		}
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			intent.RSAPadding = RSAPaddingPSS
			intent.Hash = pss.Hash
			if intent.Hash == 0 {
				intent.Hash = hash
			}
			saltLength, err := pssSaltLength(s.publicKey, intent.Hash, pss.SaltLength)
			if err != nil {
				return Intent{}, err
			}
			intent.PSSSaltLength = saltLength
		} else if _, custom := signatureOptions(opts); !custom {
			intent.RSAPadding = RSAPaddingPKCS1v15
		}
		if intent.RSAPadding == "" {
			intent.RSAPadding = s.padding
		}
		if intent.RSAPadding == RSAPaddingPSS && intent.PSSSaltLength == 0 {
			saltLength, err := pssSaltLength(s.publicKey, intent.Hash, rsa.PSSSaltLengthAuto)
			if err != nil {
				return Intent{}, err
			}
			intent.PSSSaltLength = saltLength
		}
	case AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521:
		if _, custom := signatureOptions(opts); !custom {
			intent.Prehashed = !messageLevel
		}
	case AlgorithmEd25519:
		if _, custom := signatureOptions(opts); !custom {
			intent.Prehashed = opts != nil && opts.HashFunc() != 0
		}
		if options, ok := opts.(*ed25519.Options); ok {
			intent.Hash = options.Hash
			intent.Context = []byte(options.Context)
		}
	case AlgorithmEd448:
		if _, custom := signatureOptions(opts); !custom {
			intent.Prehashed = opts != nil && opts.HashFunc() != 0
		}
	case AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87,
		AlgorithmDilithium2, AlgorithmDilithium3, AlgorithmDilithium5, AlgorithmFalcon512, AlgorithmFalcon1024, AlgorithmSPHINCSPlus, AlgorithmComposite, AlgorithmHybrid,
		AlgorithmSLHDSASHA2128S, AlgorithmSLHDSASHAKE128S, AlgorithmSLHDSASHA2128F, AlgorithmSLHDSASHAKE128F,
		AlgorithmSLHDSASHA2192S, AlgorithmSLHDSASHAKE192S, AlgorithmSLHDSASHA2192F, AlgorithmSLHDSASHAKE192F,
		AlgorithmSLHDSASHA2256S, AlgorithmSLHDSASHAKE256S, AlgorithmSLHDSASHA2256F, AlgorithmSLHDSASHAKE256F,
		AlgorithmHSS, AlgorithmLMS, AlgorithmXMSS, AlgorithmXMSSMT:
		if intent.ExternalMu && len(input) != 64 {
			return Intent{}, fmt.Errorf("pkcs11: ML-DSA external mu must be exactly 64 bytes, got %d", len(input))
		}
	}
	return intent, nil
}

// signatureOptions accepts both value and pointer forms so callers can use a
// short literal or pass a reusable mutable option object through crypto.Signer.
func signatureOptions(opts crypto.SignerOpts) (SignatureOptions, bool) {
	switch value := opts.(type) {
	case SignatureOptions:
		return value, true
	case *SignatureOptions:
		if value != nil {
			return *value, true
		}
	}
	return SignatureOptions{}, false
}

func defaultSignatureHash(algorithm Algorithm) crypto.Hash {
	switch algorithm {
	case AlgorithmRSA, AlgorithmECDSAP256:
		return crypto.SHA256
	case AlgorithmECDSAP384:
		return crypto.SHA384
	case AlgorithmECDSAP521:
		return crypto.SHA512
	default:
		return 0
	}
}

func normalizeSignatureOptions(algorithm Algorithm, options SignatureOptions) (SignatureOptions, error) {
	if options.Algorithm != "" && algorithm != "" && options.Algorithm != algorithm {
		return SignatureOptions{}, fmt.Errorf("pkcs11: key algorithm %q does not match requested %q", algorithm, options.Algorithm)
	}
	if algorithm == "" {
		algorithm = options.Algorithm
	}
	if algorithm == "" {
		return SignatureOptions{}, fmt.Errorf("pkcs11: signature algorithm is required")
	}
	options.Algorithm = algorithm
	if options.Hash == 0 && (algorithm == AlgorithmRSA || algorithm == AlgorithmECDSAP256 || algorithm == AlgorithmECDSAP384 || algorithm == AlgorithmECDSAP521) {
		options.Hash = defaultSignatureHash(algorithm)
	}
	if algorithm == AlgorithmRSA && options.RSAPadding == "" {
		options.RSAPadding = RSAPaddingPSS
	}
	if options.ExternalMu {
		if algorithm != AlgorithmMLDSA44 && algorithm != AlgorithmMLDSA65 && algorithm != AlgorithmMLDSA87 {
			return SignatureOptions{}, fmt.Errorf("pkcs11: external mu is defined only for ML-DSA")
		}
		if options.Hash != 0 || options.Prehashed {
			return SignatureOptions{}, fmt.Errorf("pkcs11: external mu cannot be combined with hash or prehash options")
		}
	}
	return options, nil
}

func signatureIntent(operation Operation, algorithm Algorithm, options SignatureOptions) (Intent, error) {
	options, err := normalizeSignatureOptions(algorithm, options)
	if err != nil {
		return Intent{}, err
	}
	return Intent{
		Operation:          operation,
		Algorithm:          options.Algorithm,
		Hash:               options.Hash,
		Prehashed:          options.Prehashed,
		ExternalMu:         options.ExternalMu,
		RSAPadding:         options.RSAPadding,
		PSSSaltLength:      options.PSSSaltLength,
		Context:            append([]byte(nil), options.Context...),
		Hedge:              options.Hedge,
		MechanismOverride:  options.MechanismOverride,
		MechanismParameter: options.MechanismParameter,
	}, nil
}

// Sign performs a single-part signature using an existing private key. Unlike
// crypto.Signer, this method accepts a context and can sign either a complete
// message or a precomputed digest according to options.Prehashed.
func (c *Client) Sign(ctx context.Context, private ObjectRef, data []byte, options SignatureOptions) ([]byte, error) {
	algorithm := private.Algorithm
	intent, err := signatureIntent(OperationSign, algorithm, options)
	if err != nil {
		return nil, err
	}
	return c.sign(ctx, private, intent, data)
}

func (c *Client) sign(ctx context.Context, private ObjectRef, intent Intent, input []byte) ([]byte, error) {
	if intent.ExternalMu && len(input) != 64 {
		return nil, fmt.Errorf("pkcs11: ML-DSA external mu must be exactly 64 bytes, got %d", len(input))
	}
	route, err := c.Resolve(intent)
	if err != nil {
		return nil, err
	}
	input, err = prepareSignatureInput(route.Intent, input)
	if err != nil {
		return nil, err
	}

	idempotent := !IsStatefulSignatureAlgorithm(intent.Algorithm)
	switch route.Execution.Replay {
	case RouteReplaySafe:
		idempotent = true
	case RouteReplayNever:
		idempotent = false
	}

	var signature []byte
	err = c.withSession(ctx, sessionOptions{
		Operation: "sign", ReadWrite: route.Execution.ReadWrite, Idempotent: idempotent,
	}, func(session *sessionLease) error {
		device := session.currentDevice()
		if device.vendor != nil {
			vendorSignature, handled, hookErr := device.vendor.Sign(ctx, session, private, route, input)
			if hookErr != nil {
				return hookErr
			}
			if handled {
				signature = append([]byte(nil), vendorSignature...)
				return nil
			}
		}

		handle, resolveErr := session.Resolve(private)
		if resolveErr != nil {
			return resolveErr
		}
		if initErr := session.SignInit([]*raw.Mechanism{route.Mechanism}, handle); initErr != nil {
			session.MarkBroken()
			return initErr
		}
		signature, err = session.Sign(input)
		if err != nil {
			session.MarkBroken()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if intent.Algorithm == AlgorithmECDSAP256 || intent.Algorithm == AlgorithmECDSAP384 || intent.Algorithm == AlgorithmECDSAP521 {
		return ecdsaRawToDER(signature)
	}
	return signature, nil
}

// ecdsaRawToDER converts the fixed-width r||s representation required by
// PKCS #11 into the ASN.1 SEQUENCE returned by Go's crypto.Signer implementations.
func ecdsaRawToDER(signature []byte) ([]byte, error) {
	if len(signature) == 0 || len(signature)%2 != 0 {
		return nil, fmt.Errorf("pkcs11: invalid raw ECDSA signature length %d", len(signature))
	}
	half := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:half])
	s := new(big.Int).SetBytes(signature[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, fmt.Errorf("pkcs11: raw ECDSA signature contains a zero scalar")
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// ecdsaDERToRaw validates a Go-style ASN.1 signature and left-pads each scalar
// to the curve width expected by C_Verify.
func ecdsaDERToRaw(signature []byte, width int) ([]byte, error) {
	var value struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &value)
	if err != nil || len(rest) != 0 || value.R == nil || value.S == nil {
		if err == nil {
			err = fmt.Errorf("invalid DER ECDSA signature")
		}
		return nil, fmt.Errorf("pkcs11: decode ECDSA signature: %w", err)
	}
	if width <= 0 || value.R.Sign() <= 0 || value.S.Sign() <= 0 || value.R.BitLen() > width*8 || value.S.BitLen() > width*8 {
		return nil, fmt.Errorf("pkcs11: ECDSA signature values are outside the %d-byte field width", width)
	}
	out := make([]byte, width*2)
	value.R.FillBytes(out[:width])
	value.S.FillBytes(out[width:])
	return out, nil
}

// unwrapOctetString accepts both the DER OCTET STRING form commonly used for
// CKA_EC_POINT and providers that return the point bytes directly.
func unwrapOctetString(value []byte) []byte {
	var out []byte
	if rest, err := asn1.Unmarshal(value, &out); err == nil && len(rest) == 0 {
		return out
	}
	return value
}

func (c *Client) loadPublicKey(ctx context.Context, object ObjectRef, algorithm Algorithm) (crypto.PublicKey, error) {
	// Give the selected module first opportunity to decode a proprietary public
	// representation or derive a temporary verification object. A read/write
	// session is used because some provider object models implement this as a
	// derivation even though the logical operation is read-only.
	device := c.currentDevice()
	if device.vendor != nil {
		var publicKey crypto.PublicKey
		var handled bool
		err := c.withSession(ctx, sessionOptions{
			Operation: "vendor-load-public-key", ReadWrite: true, Idempotent: true,
		}, func(session *sessionLease) error {
			var hookErr error
			publicKey, handled, hookErr = device.vendor.LoadPublicKey(ctx, session, object, algorithm)
			return hookErr
		})
		if err != nil {
			return nil, err
		}
		if handled {
			return publicKey, nil
		}
	}

	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_MODULUS, nil),
		raw.NewAttribute(raw.CKA_PUBLIC_EXPONENT, nil),
		raw.NewAttribute(raw.CKA_EC_POINT, nil),
		raw.NewAttribute(raw.CKA_EC_PARAMS, nil),
		raw.NewAttribute(raw.CKA_VALUE, nil),
		raw.NewAttribute(raw.CKA_PUBLIC_KEY_INFO, nil),
	}
	values, queryErr := c.Attributes(ctx, object, attributes...)
	if queryErr != nil && len(values) == 0 {
		return nil, queryErr
	}
	byType := make(map[uint][]byte)
	for _, attribute := range values {
		if attribute != nil {
			byType[attribute.Type] = attribute.Value
		}
	}
	switch algorithm {
	case AlgorithmRSA:
		n := new(big.Int).SetBytes(byType[raw.CKA_MODULUS])
		e := new(big.Int).SetBytes(byType[raw.CKA_PUBLIC_EXPONENT])
		if n.Sign() == 0 || !e.IsInt64() || e.Int64() < 2 {
			return nil, fmt.Errorf("pkcs11: invalid RSA public attributes")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521:
		var curve elliptic.Curve
		switch algorithm {
		case AlgorithmECDSAP256:
			curve = elliptic.P256()
		case AlgorithmECDSAP384:
			curve = elliptic.P384()
		case AlgorithmECDSAP521:
			curve = elliptic.P521()
		}
		point := unwrapOctetString(byType[raw.CKA_EC_POINT])
		x, y := elliptic.Unmarshal(curve, point)
		if x == nil {
			return nil, fmt.Errorf("pkcs11: invalid EC point")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case AlgorithmEd25519:
		point := unwrapOctetString(byType[raw.CKA_EC_POINT])
		if len(point) == 0 {
			point = byType[raw.CKA_VALUE]
		}
		if len(point) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pkcs11: Ed25519 public key is %d bytes", len(point))
		}
		return ed25519.PublicKey(append([]byte(nil), point...)), nil
	default:
		encoding := byType[raw.CKA_PUBLIC_KEY_INFO]
		if len(encoding) == 0 {
			encoding = byType[raw.CKA_VALUE]
		}
		if len(encoding) == 0 {
			encoding = unwrapOctetString(byType[raw.CKA_EC_POINT])
		}
		if len(encoding) == 0 && queryErr != nil {
			return nil, queryErr
		}
		if len(encoding) == 0 {
			return nil, fmt.Errorf("pkcs11: public-key encoding is unavailable for %s", algorithm)
		}
		return OpaquePublicKey{Algorithm: algorithm, Encoding: append([]byte(nil), encoding...)}, nil
	}
}

// Verify performs a single-part verification using an existing public key.
// ECDSA signatures use the DER encoding expected by Go's crypto package; the
// driver converts them to the raw r||s form required by PKCS #11.
func (c *Client) Verify(ctx context.Context, public ObjectRef, data, signature []byte, options SignatureOptions) error {
	intent, err := signatureIntent(OperationVerify, public.Algorithm, options)
	if err != nil {
		return err
	}
	route, err := c.Resolve(intent)
	if err != nil {
		return err
	}
	data, err = prepareSignatureInput(route.Intent, data)
	if err != nil {
		return err
	}
	if intent.Algorithm == AlgorithmECDSAP256 || intent.Algorithm == AlgorithmECDSAP384 || intent.Algorithm == AlgorithmECDSAP521 {
		width := 32
		if intent.Algorithm == AlgorithmECDSAP384 {
			width = 48
		}
		if intent.Algorithm == AlgorithmECDSAP521 {
			width = 66
		}
		signature, err = ecdsaDERToRaw(signature, width)
		if err != nil {
			return err
		}
	}

	idempotent := true
	if route.Execution.Replay == RouteReplayNever {
		idempotent = false
	}
	return c.withSession(ctx, sessionOptions{
		Operation: "verify", ReadWrite: route.Execution.ReadWrite, Idempotent: idempotent,
	}, func(session *sessionLease) error {
		device := session.currentDevice()
		if device.vendor != nil {
			handled, hookErr := device.vendor.Verify(ctx, session, public, route, data, signature)
			if hookErr != nil {
				return hookErr
			}
			if handled {
				return nil
			}
		}

		handle, resolveErr := session.Resolve(public)
		if resolveErr != nil {
			return resolveErr
		}
		if initErr := session.VerifyInit([]*raw.Mechanism{route.Mechanism}, handle); initErr != nil {
			session.MarkBroken()
			return initErr
		}
		if verifyErr := session.Verify(data, signature); verifyErr != nil {
			if !raw.IsError(verifyErr, raw.CKR_SIGNATURE_INVALID) {
				session.MarkBroken()
			}
			return verifyErr
		}
		return nil
	})
}

// Decrypter implements crypto.Decrypter using a managed token-resident RSA private key.
// Like Signer, it resolves the private object for each operation and can recover
// from session or connection replacement when a durable locator is available.
type Decrypter struct {
	client    *Client
	private   ObjectRef
	publicKey crypto.PublicKey
}

func newDecrypter(ctx context.Context, client *Client, private, public ObjectRef) (*Decrypter, error) {
	if private.Algorithm == "" {
		private.Algorithm = AlgorithmRSA
	}
	if public.Handle == 0 && public.ID == nil && public.Label == "" && public.UniqueID == "" {
		public = private
		public.Class = raw.CKO_PUBLIC_KEY
	}
	key, err := client.loadPublicKey(ctx, public, private.Algorithm)
	if err != nil {
		return nil, err
	}
	return &Decrypter{client: client, private: private, publicKey: key}, nil
}

// Public returns the public key corresponding to the token-resident private key.
func (d *Decrypter) Public() crypto.PublicKey { return d.publicKey }

// Decrypt implements crypto.Decrypter for RSA PKCS #1 v1.5 and OAEP. Because
// that interface has no context, this method uses context.Background. Call
// DecryptContext to propagate a deadline through session acquisition and recovery.
func (d *Decrypter) Decrypt(randomSource io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return d.DecryptContext(context.Background(), randomSource, ciphertext, opts)
}

// DecryptContext performs an RSA private-key operation while honoring ctx.
// Its option handling matches crypto/rsa.PrivateKey.Decrypt, including the
// constant-behavior fallback requested by rsa.PKCS1v15DecryptOptions.
func (d *Decrypter) DecryptContext(ctx context.Context, randomSource io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if d == nil || d.client == nil {
		return nil, fmt.Errorf("pkcs11: decrypter is nil or closed")
	}
	// Match crypto/rsa.PrivateKey.Decrypt: nil options select PKCS#1 v1.5,
	// while OAEP is selected explicitly with *rsa.OAEPOptions.
	intent := Intent{Operation: OperationDecrypt, Algorithm: AlgorithmRSA, Hash: crypto.SHA256, RSAPadding: RSAPaddingPKCS1v15}
	sessionKeyLength := 0
	switch value := opts.(type) {
	case *rsa.OAEPOptions:
		intent.RSAPadding = RSAPaddingOAEP
		if value != nil {
			intent.Hash = value.Hash
			intent.OAEPLabel = value.Label
		}
	case *rsa.PKCS1v15DecryptOptions:
		if value != nil {
			sessionKeyLength = value.SessionKeyLen
		}
	case nil:
	case crypto.Hash:
		// Retained as a convenience extension: a bare hash selects RSA-OAEP.
		intent.RSAPadding = RSAPaddingOAEP
		intent.Hash = value
	default:
		return nil, fmt.Errorf("pkcs11: unsupported decrypter options %T", opts)
	}
	if sessionKeyLength < 0 {
		return nil, fmt.Errorf("pkcs11: invalid PKCS#1 session-key length %d", sessionKeyLength)
	}

	var fallback []byte
	if sessionKeyLength > 0 {
		// Generate the fallback before entering the HSM so valid and invalid padding
		// paths both have a session key available without a second conditional RNG call.
		if randomSource == nil {
			randomSource = rand.Reader
		}
		fallback = make([]byte, sessionKeyLength)
		if _, err := io.ReadFull(randomSource, fallback); err != nil {
			return nil, fmt.Errorf("pkcs11: generate PKCS#1 session-key fallback: %w", err)
		}
	}

	route, err := d.client.Resolve(intent)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	err = d.client.withSession(ctx, sessionOptions{Operation: "decrypt"}, func(session *sessionLease) error {
		handle, err := resolveObject(session, d.private)
		if err != nil {
			return err
		}
		if err := session.DecryptInit([]*raw.Mechanism{route.Mechanism}, handle); err != nil {
			session.MarkBroken()
			return err
		}
		plaintext, err = session.Decrypt(ciphertext)
		if err != nil && !isPKCS1PaddingError(err) {
			session.MarkBroken()
		}
		return err
	})
	if sessionKeyLength == 0 {
		return plaintext, err
	}
	// PKCS1v15DecryptOptions asks the implementation not to reveal whether
	// padding was valid. Only padding/data errors are suppressed; availability,
	// authentication, and device errors still reach the caller.
	if err != nil {
		if isPKCS1PaddingError(err) {
			return fallback, nil
		}
		return nil, err
	}
	if len(plaintext) != sessionKeyLength {
		return fallback, nil
	}
	copy(fallback, plaintext)
	return fallback, nil
}

// isPKCS1PaddingError identifies errors that rsa.PKCS1v15DecryptOptions asks
// DecryptContext to hide by returning the random fallback key.
func isPKCS1PaddingError(err error) bool {
	return raw.IsError(err, raw.CKR_ENCRYPTED_DATA_INVALID) ||
		raw.IsError(err, raw.CKR_ENCRYPTED_DATA_LEN_RANGE) ||
		raw.IsError(err, raw.CKR_DATA_INVALID) ||
		raw.IsError(err, raw.CKR_DATA_LEN_RANGE)
}

// GenerateSigner creates a key pair and returns an immediately usable crypto.Signer.
// If public-key loading fails, it makes a best-effort attempt to destroy every
// newly generated object before returning the construction error.
func (c *Client) GenerateSigner(ctx context.Context, options KeyPairOptions, signerConfig SignerConfig) (*Signer, KeyPair, error) {
	pair, err := c.GenerateKeyPair(ctx, options)
	if err != nil {
		return nil, KeyPair{}, err
	}
	signerConfig.Private, signerConfig.Public, signerConfig.Algorithm = pair.Private, pair.Public, options.Algorithm
	signer, err := newSigner(ctx, c, signerConfig)
	if err != nil {
		_ = c.Destroy(ctx, pair.Private)
		if !sameObjectRef(pair.Public, pair.Private) {
			_ = c.Destroy(ctx, pair.Public)
		}
		return nil, KeyPair{}, err
	}
	return signer, pair, nil
}

var _ crypto.Signer = (*Signer)(nil)
var _ crypto.MessageSigner = (*Signer)(nil)
var _ crypto.Decrypter = (*Decrypter)(nil)
