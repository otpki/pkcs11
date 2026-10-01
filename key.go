package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/otpki/pkcs11/raw"
)

// ObjectRef identifies an object by a transient handle and/or durable token attributes.
// Durable ID or UniqueID values allow recovery after session replacement or failover.
type ObjectRef struct {
	// Handle is a fast, session-visible native handle. It may become stale after
	// reconnect, hotplug, module reinitialization, or failover.
	Handle raw.ObjectHandle
	// Class and KeyType constrain durable lookup and prevent resolving an object
	// of the wrong semantic type when labels or IDs are reused.
	Class   uint
	KeyType uint
	// Algorithm records the high-level routing intent; it is not itself a token
	// lookup attribute.
	Algorithm Algorithm
	// UniqueID is the PKCS #11 3.x unique object identifier when available.
	UniqueID string
	// Label and ID are durable lookup attributes used when Handle is unavailable
	// or stale. ID is defensively copied by constructors that return ObjectRef.
	Label string
	ID    []byte
}

// KeyPair contains the public and private object references created or found together.
type KeyPair struct {
	// Public identifies the verification, encryption, or encapsulation object.
	Public ObjectRef
	// Private identifies the signing, decryption, or decapsulation object. Some
	// vendor stateful-signature backends intentionally return the same object in
	// both fields because the HSM stores one combined stateful key.
	Private ObjectRef
}

// ObjectPolicy describes common PKCS #11 storage and mutability attributes.
type ObjectPolicy struct {
	// Token maps to CKA_TOKEN. False requests a session object.
	Token bool
	// Private maps to CKA_PRIVATE and controls visibility before login.
	Private bool
	// Sensitive maps to CKA_SENSITIVE for private and secret keys.
	Sensitive bool
	// Extractable maps to CKA_EXTRACTABLE for private and secret keys.
	Extractable bool
	// Modifiable, Copyable, and Destroyable map to their corresponding object
	// management attributes. Tokens may further restrict these capabilities.
	Modifiable  bool
	Copyable    bool
	Destroyable bool
	// AlwaysAuthenticate maps to CKA_ALWAYS_AUTHENTICATE on private keys and
	// causes context-specific login before each protected operation.
	AlwaysAuthenticate bool
}

// DefaultPrivateKeyPolicy returns a persistent, sensitive, non-extractable private-key policy.
func DefaultPrivateKeyPolicy() ObjectPolicy {
	return ObjectPolicy{Token: true, Private: true, Sensitive: true, Extractable: false, Modifiable: true, Copyable: true, Destroyable: true}
}

// DefaultPublicKeyPolicy returns a persistent public-key policy.
func DefaultPublicKeyPolicy() ObjectPolicy {
	return ObjectPolicy{Token: true, Private: false, Sensitive: false, Extractable: true, Modifiable: true, Copyable: true, Destroyable: true}
}

// DefaultSecretKeyPolicy returns a persistent, sensitive, non-extractable secret-key policy.
func DefaultSecretKeyPolicy() ObjectPolicy {
	return ObjectPolicy{Token: true, Private: true, Sensitive: true, Extractable: false, Modifiable: true, Copyable: true, Destroyable: true}
}

// TemplateContext describes the object being built for a TemplatePolicy callback.
type TemplateContext struct {
	// Operation identifies the high-level action constructing the template.
	Operation Operation
	// Algorithm identifies the selected high-level algorithm.
	Algorithm Algorithm
	// ObjectClass and KeyType are the invariant PKCS #11 identifiers that the
	// policy must preserve.
	ObjectClass uint
	KeyType     uint
	// Label and ID are the requested durable object identity.
	Label string
	ID    []byte
}

// TemplatePolicy can add or rewrite attributes after the driver builds its
// standard algorithm and policy template. Explicit raw attributes supplied in
// the operation options are merged afterward and therefore take precedence.
//
// Implementations must preserve CKA_CLASS, CKA_KEY_TYPE, and any required
// CKA_PARAMETER_SET value; the driver validates those invariants before calling
// the module. Vendor compatibility normalization still runs internally.
type TemplatePolicy interface {
	ApplyTemplate(TemplateContext, []*raw.Attribute) ([]*raw.Attribute, error)
}

// HSSParameters selects the LMS/LM-OTS tree hierarchy for CKM_HSS_KEY_PAIR_GEN.
// Values are the RFC 8554 / SP 800-208 numeric type encodings accepted by the token.
type HSSParameters struct {
	// Levels is the number of LMS trees in the hierarchy. Zero derives the value
	// from LMSTypes. AlgorithmLMS requires exactly one level.
	Levels uint
	// LMSTypes and LMOTSTypes contain one numeric selector per hierarchy level.
	// Their lengths must both equal Levels.
	LMSTypes   []uint
	LMOTSTypes []uint
}

func (p HSSParameters) attributes() ([]*raw.Attribute, error) {
	if p.Levels == 0 {
		p.Levels = uint(len(p.LMSTypes))
	}
	if p.Levels == 0 {
		return nil, errors.New("pkcs11: HSS levels are required")
	}
	if len(p.LMSTypes) != int(p.Levels) || len(p.LMOTSTypes) != int(p.Levels) {
		return nil, fmt.Errorf("pkcs11: HSS levels (%d) must match LMS (%d) and LM-OTS (%d) type counts", p.Levels, len(p.LMSTypes), len(p.LMOTSTypes))
	}
	return []*raw.Attribute{
		raw.NewAttribute(raw.CKA_HSS_LEVELS, p.Levels),
		raw.NewAttribute(raw.CKA_HSS_LMS_TYPES, p.LMSTypes),
		raw.NewAttribute(raw.CKA_HSS_LMOTS_TYPES, p.LMOTSTypes),
	}, nil
}

// KeyPairOptions controls high-level asymmetric or PQC key-pair generation.
// Raw attributes and mechanism overrides remain available for expert use.
type KeyPairOptions struct {
	// Algorithm selects key type, generation mechanism, default usages, and any
	// standard-first vendor fallback.
	Algorithm Algorithm
	// Label and ID become CKA_LABEL and CKA_ID on both halves of the pair.
	Label string
	ID    []byte

	// RSA-specific generation parameters. Zero values select a 3072-bit key
	// and public exponent 65537.
	RSABits     uint
	RSAExponent *big.Int

	// ParameterSet overrides CKA_PARAMETER_SET for algorithms whose selectors
	// are intentionally application-controlled, such as XMSS/XMSSMT.
	ParameterSet uint

	// HSS describes an HSS hierarchy. AlgorithmLMS uses the same structure
	// with exactly one level. A vendor module may encode these values into its
	// vendor generation parameter block automatically.
	HSS *HSSParameters

	// MechanismOverride is an expert escape hatch. Automatic routing should be
	// preferred so standard and vendor-specific implementations remain
	// interchangeable.
	MechanismOverride *uint
	// MechanismParameter replaces the parameter selected by automatic routing.
	// Prefer typed raw or vendors/<vendor> parameter values over UnsafeParameter.
	MechanismParameter any

	// PublicPolicy and PrivatePolicy replace the corresponding secure defaults.
	PublicPolicy  *ObjectPolicy
	PrivatePolicy *ObjectPolicy
	// PublicAttributes and PrivateAttributes are merged last for expert control.
	// Invariant class, key type, and parameter-set values are still validated.
	PublicAttributes  []*raw.Attribute
	PrivateAttributes []*raw.Attribute
	// TemplatePolicy adjusts each driver-built template before the explicit raw
	// attribute slices above are merged.
	TemplatePolicy TemplatePolicy
}

// SecretKeyOptions controls symmetric or MAC-key generation.
type SecretKeyOptions struct {
	// Algorithm selects the key type, generation mechanism, value length, and
	// default usage attributes.
	Algorithm Algorithm
	// Label and ID become CKA_LABEL and CKA_ID.
	Label string
	ID    []byte

	// MechanismOverride bypasses automatic standard-first routing.
	MechanismOverride *uint
	// MechanismParameter replaces the automatically selected parameter.
	MechanismParameter any

	// Policy replaces DefaultSecretKeyPolicy.
	Policy *ObjectPolicy
	// Attributes are merged last for expert control, subject to invariant checks.
	Attributes []*raw.Attribute
	// TemplatePolicy adjusts the driver-built template before Attributes are merged.
	TemplatePolicy TemplatePolicy
}

// policyAttributes translates the common policy into attributes applicable to
// class. Sensitive/extractable are omitted for public objects, and
// always-authenticate is meaningful only for private keys.
func policyAttributes(policy ObjectPolicy, class uint) []*raw.Attribute {
	attributes := []*raw.Attribute{
		raw.NewAttribute(raw.CKA_TOKEN, policy.Token),
		raw.NewAttribute(raw.CKA_PRIVATE, policy.Private),
		raw.NewAttribute(raw.CKA_MODIFIABLE, policy.Modifiable),
		raw.NewAttribute(raw.CKA_COPYABLE, policy.Copyable),
		raw.NewAttribute(raw.CKA_DESTROYABLE, policy.Destroyable),
	}
	if class == raw.CKO_PRIVATE_KEY || class == raw.CKO_SECRET_KEY {
		attributes = append(attributes,
			raw.NewAttribute(raw.CKA_SENSITIVE, policy.Sensitive),
			raw.NewAttribute(raw.CKA_EXTRACTABLE, policy.Extractable),
		)
	}
	if class == raw.CKO_PRIVATE_KEY {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ALWAYS_AUTHENTICATE, policy.AlwaysAuthenticate))
	}
	return attributes
}

// mergeAttributes combines templates by attribute type. The first occurrence
// fixes output order and the last occurrence supplies the value, allowing later
// policy/user groups to override defaults without producing duplicate types.
// Values and nested templates are deep-copied to avoid aliasing caller memory.
func mergeAttributes(groups ...[]*raw.Attribute) []*raw.Attribute {
	order := make([]uint, 0)
	values := make(map[uint]*raw.Attribute)
	for _, group := range groups {
		for _, attribute := range group {
			if attribute == nil {
				continue
			}
			if _, exists := values[attribute.Type]; !exists {
				order = append(order, attribute.Type)
			}
			copyAttribute := &raw.Attribute{Type: attribute.Type, Value: append([]byte(nil), attribute.Value...)}
			if attribute.Children != nil {
				copyAttribute.Children = mergeAttributes(attribute.Children)
			}
			values[attribute.Type] = copyAttribute
		}
	}
	result := make([]*raw.Attribute, 0, len(order))
	for _, typ := range order {
		result = append(result, values[typ])
	}
	return result
}

// commonIdentity emits only explicitly supplied identity attributes. A nil ID
// means "unspecified" while a non-nil empty slice requests an empty CKA_ID.
func commonIdentity(label string, id []byte) []*raw.Attribute {
	var attributes []*raw.Attribute
	if label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, label))
	}
	if id != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, id))
	}
	return attributes
}

// usageAttributes supplies conservative operation permissions for each
// high-level algorithm and object class. Callers can override individual flags
// through explicit attributes, subject to token policy.
func usageAttributes(algorithm Algorithm, class uint) []*raw.Attribute {
	public := class == raw.CKO_PUBLIC_KEY
	private := class == raw.CKO_PRIVATE_KEY
	secret := class == raw.CKO_SECRET_KEY
	switch algorithm {
	case AlgorithmRSA:
		if public {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_VERIFY, true), raw.NewAttribute(raw.CKA_ENCRYPT, true), raw.NewAttribute(raw.CKA_WRAP, true)}
		}
		if private {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_SIGN, true), raw.NewAttribute(raw.CKA_DECRYPT, true), raw.NewAttribute(raw.CKA_UNWRAP, true)}
		}
	case AlgorithmECDSAP256, AlgorithmECDSAP384, AlgorithmECDSAP521, AlgorithmEd25519, AlgorithmEd448, AlgorithmHSS, AlgorithmXMSS, AlgorithmXMSSMT,
		AlgorithmDilithium2, AlgorithmDilithium3, AlgorithmDilithium5, AlgorithmFalcon512, AlgorithmFalcon1024, AlgorithmSPHINCSPlus, AlgorithmComposite, AlgorithmHybrid,
		AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87,
		AlgorithmSLHDSASHA2128S, AlgorithmSLHDSASHAKE128S, AlgorithmSLHDSASHA2128F, AlgorithmSLHDSASHAKE128F,
		AlgorithmSLHDSASHA2192S, AlgorithmSLHDSASHAKE192S, AlgorithmSLHDSASHA2192F, AlgorithmSLHDSASHAKE192F,
		AlgorithmSLHDSASHA2256S, AlgorithmSLHDSASHAKE256S, AlgorithmSLHDSASHA2256F, AlgorithmSLHDSASHAKE256F:
		if public {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_VERIFY, true)}
		}
		if private {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_SIGN, true)}
		}
	case AlgorithmMLKEM512, AlgorithmMLKEM768, AlgorithmMLKEM1024, AlgorithmKyber512, AlgorithmKyber768, AlgorithmKyber1024:
		if public {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_ENCAPSULATE, true)}
		}
		if private {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_DECAPSULATE, true)}
		}
	case AlgorithmAES128, AlgorithmAES192, AlgorithmAES256:
		if secret {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_ENCRYPT, true), raw.NewAttribute(raw.CKA_DECRYPT, true), raw.NewAttribute(raw.CKA_WRAP, true), raw.NewAttribute(raw.CKA_UNWRAP, true)}
		}
	case AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512:
		if secret {
			return []*raw.Attribute{raw.NewAttribute(raw.CKA_SIGN, true), raw.NewAttribute(raw.CKA_VERIFY, true)}
		}
	}
	return nil
}

// applyTemplatePolicy keeps nil policy handling at call sites uniform. Invariant
// validation deliberately occurs after the policy and explicit attributes have
// both been applied.
func applyTemplatePolicy(policy TemplatePolicy, context TemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	if policy == nil {
		return attributes, nil
	}
	return policy.ApplyTemplate(context, attributes)
}

func invariantValue(attributes []*raw.Attribute, typ uint) ([]byte, bool) {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == typ {
			return attribute.Value, true
		}
	}
	return nil, false
}

// validateInvariants prevents expert hooks from silently changing the semantic
// object selected by the high-level route. Other attributes remain completely
// caller-controlled.
func validateInvariants(attributes []*raw.Attribute, class, keyType, parameterSet uint) error {
	if value, ok := invariantValue(attributes, raw.CKA_CLASS); ok {
		actual, valid := raw.ULong(value)
		if !valid || actual != class {
			return errors.New("pkcs11: template overrides CKA_CLASS with incompatible value")
		}
	}
	if value, ok := invariantValue(attributes, raw.CKA_KEY_TYPE); ok {
		actual, valid := raw.ULong(value)
		if !valid || actual != keyType {
			return errors.New("pkcs11: template overrides CKA_KEY_TYPE with incompatible value")
		}
	}
	if parameterSet != 0 {
		if value, ok := invariantValue(attributes, raw.CKA_PARAMETER_SET); ok {
			actual, valid := raw.ULong(value)
			if !valid || actual != parameterSet {
				return errors.New("pkcs11: template overrides CKA_PARAMETER_SET with incompatible value")
			}
		}
	}
	return nil
}

// GenerateSecretKey creates an AES, HMAC, or other routed secret key. The driver
// selects a standard mechanism first, builds a secure default template, applies
// TemplatePolicy, then merges explicit Attributes. The operation is not retried
// because the token may have created an object before returning an error.
func (c *Client) GenerateSecretKey(ctx context.Context, options SecretKeyOptions) (ObjectRef, error) {
	spec, ok := algorithmSpecs[options.Algorithm]
	if !ok || !spec.Secret {
		return ObjectRef{}, fmt.Errorf("pkcs11: %s is not a secret-key algorithm", options.Algorithm)
	}
	route, err := c.Resolve(Intent{Operation: OperationGenerate, Algorithm: options.Algorithm, MechanismOverride: options.MechanismOverride, MechanismParameter: options.MechanismParameter})
	if err != nil {
		return ObjectRef{}, err
	}
	if vendor := c.currentDevice().vendor; vendor != nil {
		var result ObjectRef
		var handled bool
		err = c.withSession(ctx, sessionOptions{Operation: "vendor-generate-key", ReadWrite: true}, func(session *sessionLease) error {
			var hookErr error
			result, handled, hookErr = vendor.GenerateSecretKey(ctx, session, route, options)
			return hookErr
		})
		if err != nil {
			return ObjectRef{}, err
		}
		if handled {
			return result, nil
		}
	}
	policy := DefaultSecretKeyPolicy()
	if options.Policy != nil {
		policy = *options.Policy
	}
	attributes := mergeAttributes(route.SecretTemplate, policyAttributes(policy, raw.CKO_SECRET_KEY), commonIdentity(options.Label, options.ID), usageAttributes(options.Algorithm, raw.CKO_SECRET_KEY))
	attributes, err = applyTemplatePolicy(options.TemplatePolicy, TemplateContext{Operation: OperationGenerate, Algorithm: options.Algorithm, ObjectClass: raw.CKO_SECRET_KEY, KeyType: route.KeyType, Label: options.Label, ID: options.ID}, attributes)
	if err != nil {
		return ObjectRef{}, err
	}
	attributes = mergeAttributes(attributes, options.Attributes)
	if err := validateInvariants(attributes, raw.CKO_SECRET_KEY, route.KeyType, route.ParameterSet); err != nil {
		return ObjectRef{}, err
	}
	var handle raw.ObjectHandle
	err = c.withSession(ctx, sessionOptions{Operation: "generate-key", ReadWrite: true}, func(session *sessionLease) error {
		var generateErr error
		handle, generateErr = session.GenerateKey(ctx, []*raw.Mechanism{route.Mechanism}, attributes)
		if generateErr != nil {
			session.MarkBroken()
		}
		return generateErr
	})
	if err != nil {
		return ObjectRef{}, err
	}
	return ObjectRef{Handle: handle, Class: raw.CKO_SECRET_KEY, KeyType: route.KeyType, Algorithm: options.Algorithm, Label: options.Label, ID: append([]byte(nil), options.ID...)}, nil
}

// defaultLMSParameters selects the small, widely implemented RFC 8554
// SHA-256/32-byte LMS tree with height 10 and LM-OTS Winternitz parameter 4.
// Applications that need a different capacity/performance tradeoff should set
// KeyPairOptions.HSS explicitly.
func defaultLMSParameters() HSSParameters {
	return HSSParameters{Levels: 1, LMSTypes: []uint{6}, LMOTSTypes: []uint{3}}
}

// GenerateKeyPair creates a routed asymmetric or PQC key pair with automatic
// standard-first vendor adaptation. It applies secure default policies and
// usage attributes, then TemplatePolicy and explicit per-half attributes.
//
// Key generation is intentionally single-attempt: a transport or session error
// can be reported after an HSM has already persisted one or both key objects.
// Stateful signature keys are required to remain sensitive and non-extractable.
func (c *Client) GenerateKeyPair(ctx context.Context, options KeyPairOptions) (KeyPair, error) {
	spec, ok := algorithmSpecs[options.Algorithm]
	if !ok || !spec.KeyPair {
		return KeyPair{}, fmt.Errorf("pkcs11: %s is not a key-pair algorithm", options.Algorithm)
	}
	route, err := c.Resolve(Intent{Operation: OperationGenerate, Algorithm: options.Algorithm, MechanismOverride: options.MechanismOverride, MechanismParameter: options.MechanismParameter})
	if err != nil {
		return KeyPair{}, err
	}
	privatePolicy := DefaultPrivateKeyPolicy()
	if options.PrivatePolicy != nil {
		privatePolicy = *options.PrivatePolicy
	}
	if vendor := c.currentDevice().vendor; vendor != nil {
		var result KeyPair
		var handled bool
		err = c.withSession(ctx, sessionOptions{Operation: "vendor-generate-key-pair", ReadWrite: true}, func(session *sessionLease) error {
			var hookErr error
			result, handled, hookErr = vendor.GenerateKeyPair(ctx, session, route, options)
			return hookErr
		})
		if err != nil {
			return KeyPair{}, err
		}
		if handled {
			return result, nil
		}
	}
	if options.Algorithm == AlgorithmRSA {
		bits := options.RSABits
		if bits == 0 {
			bits = 3072
		}
		exponent := options.RSAExponent
		if exponent == nil {
			exponent = big.NewInt(65537)
		}
		route.PublicTemplate = mergeAttributes(route.PublicTemplate, []*raw.Attribute{raw.NewAttribute(raw.CKA_MODULUS_BITS, bits), raw.NewAttribute(raw.CKA_PUBLIC_EXPONENT, exponent)})
	}
	if options.ParameterSet != 0 {
		if route.OmitParameterSetAttribute {
			if route.ParameterSet != 0 && options.ParameterSet != route.ParameterSet {
				return KeyPair{}, fmt.Errorf("pkcs11: parameter set %d does not match the vendor route for %s", options.ParameterSet, options.Algorithm)
			}
			// The selected vendor carries the parameter set in its mechanism
			// parameter block. Do not leak CKA_PARAMETER_SET into its template.
			route.ParameterSet = options.ParameterSet
		} else {
			route.ParameterSet = options.ParameterSet
			parameterAttribute := []*raw.Attribute{raw.NewAttribute(raw.CKA_PARAMETER_SET, options.ParameterSet)}
			route.PublicTemplate = mergeAttributes(route.PublicTemplate, parameterAttribute)
			route.PrivateTemplate = mergeAttributes(route.PrivateTemplate, parameterAttribute)
		}
	}
	if options.Algorithm == AlgorithmHSS || options.Algorithm == AlgorithmLMS {
		parameters := options.HSS
		if parameters == nil && options.Algorithm == AlgorithmLMS {
			defaults := defaultLMSParameters()
			parameters = &defaults
		}
		if parameters == nil {
			return KeyPair{}, errors.New("pkcs11: HSS generation requires HSS hierarchy parameters")
		}
		if options.Algorithm == AlgorithmLMS {
			levels := parameters.Levels
			if levels == 0 {
				levels = uint(len(parameters.LMSTypes))
			}
			if levels != 1 {
				return KeyPair{}, errors.New("pkcs11: LMS requires exactly one LMS/LM-OTS level")
			}
		}
		hssAttributes, hssErr := parameters.attributes()
		if hssErr != nil {
			return KeyPair{}, hssErr
		}
		// The hierarchy selectors belong to the private-key generation template;
		// the token derives the public key's top-level descriptors.
		route.PrivateTemplate = mergeAttributes(route.PrivateTemplate, hssAttributes)
	}
	publicPolicy := DefaultPublicKeyPolicy()
	if options.PublicPolicy != nil {
		publicPolicy = *options.PublicPolicy
	}
	if IsStatefulSignatureAlgorithm(options.Algorithm) {
		if !privatePolicy.Sensitive || privatePolicy.Extractable {
			return KeyPair{}, errors.New("pkcs11: stateful signature private keys must be sensitive and non-extractable")
		}
	}
	publicAttributes := mergeAttributes(route.PublicTemplate, policyAttributes(publicPolicy, raw.CKO_PUBLIC_KEY), commonIdentity(options.Label, options.ID), usageAttributes(options.Algorithm, raw.CKO_PUBLIC_KEY))
	privateAttributes := mergeAttributes(route.PrivateTemplate, policyAttributes(privatePolicy, raw.CKO_PRIVATE_KEY), commonIdentity(options.Label, options.ID), usageAttributes(options.Algorithm, raw.CKO_PRIVATE_KEY))
	publicAttributes, err = applyTemplatePolicy(options.TemplatePolicy, TemplateContext{Operation: OperationGenerate, Algorithm: options.Algorithm, ObjectClass: raw.CKO_PUBLIC_KEY, KeyType: route.KeyType, Label: options.Label, ID: options.ID}, publicAttributes)
	if err != nil {
		return KeyPair{}, err
	}
	privateAttributes, err = applyTemplatePolicy(options.TemplatePolicy, TemplateContext{Operation: OperationGenerate, Algorithm: options.Algorithm, ObjectClass: raw.CKO_PRIVATE_KEY, KeyType: route.KeyType, Label: options.Label, ID: options.ID}, privateAttributes)
	if err != nil {
		return KeyPair{}, err
	}
	publicAttributes = mergeAttributes(publicAttributes, options.PublicAttributes)
	privateAttributes = mergeAttributes(privateAttributes, options.PrivateAttributes)
	if err := validateInvariants(publicAttributes, raw.CKO_PUBLIC_KEY, route.KeyType, route.ParameterSet); err != nil {
		return KeyPair{}, err
	}
	if err := validateInvariants(privateAttributes, raw.CKO_PRIVATE_KEY, route.KeyType, route.ParameterSet); err != nil {
		return KeyPair{}, err
	}
	var publicHandle, privateHandle raw.ObjectHandle
	err = c.withSession(ctx, sessionOptions{Operation: "generate-key-pair", ReadWrite: true}, func(session *sessionLease) error {
		var generateErr error
		publicHandle, privateHandle, generateErr = session.GenerateKeyPair(ctx, []*raw.Mechanism{route.Mechanism}, publicAttributes, privateAttributes)
		if generateErr != nil {
			session.MarkBroken()
		}
		return generateErr
	})
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Public:  ObjectRef{Handle: publicHandle, Class: raw.CKO_PUBLIC_KEY, KeyType: route.KeyType, Algorithm: options.Algorithm, Label: options.Label, ID: append([]byte(nil), options.ID...)},
		Private: ObjectRef{Handle: privateHandle, Class: raw.CKO_PRIVATE_KEY, KeyType: route.KeyType, Algorithm: options.Algorithm, Label: options.Label, ID: append([]byte(nil), options.ID...)},
	}, nil
}

// HSSKeysRemaining returns the number of signatures still available for an HSS
// or LMS private key. Tokens may return raw.CK_UNAVAILABLE_INFORMATION when the
// count is unknown. The value is live mutable state and is excluded from the
// managed attribute cache by the default cache policy.
func (c *Client) HSSKeysRemaining(ctx context.Context, privateKey ObjectRef) (uint, error) {
	if privateKey.Algorithm != "" && privateKey.Algorithm != AlgorithmHSS && privateKey.Algorithm != AlgorithmLMS {
		return 0, fmt.Errorf("pkcs11: %s is not an HSS/LMS key", privateKey.Algorithm)
	}
	attributes, err := c.Attributes(ctx, privateKey, raw.NewAttribute(raw.CKA_HSS_KEYS_REMAINING, nil))
	if err != nil && len(attributes) == 0 {
		return 0, err
	}
	if len(attributes) != 1 {
		return 0, errors.New("pkcs11: token did not return CKA_HSS_KEYS_REMAINING")
	}
	remaining, ok := raw.ULong(attributes[0].Value)
	if !ok {
		return 0, errors.New("pkcs11: invalid CKA_HSS_KEYS_REMAINING encoding")
	}
	return remaining, err
}
