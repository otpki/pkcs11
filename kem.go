package pkcs11

import (
	"context"
	"errors"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// KEMOptions controls the derived secret object and optional expert mechanism override.
type KEMOptions struct {
	// Algorithm selects the KEM parameter set. When empty, Encapsulate and
	// Decapsulate inherit it from the supplied ObjectRef.
	Algorithm Algorithm
	// Label and ID are applied to the derived shared-secret object.
	Label string
	ID    []byte
	// SecretPolicy replaces the default session-object policy. The default keeps
	// the secret sensitive and non-extractable but sets CKA_TOKEN to false.
	SecretPolicy *ObjectPolicy
	// SecretAttributes are merged last and provide complete expert control over
	// non-invariant attributes of the derived object.
	SecretAttributes []*raw.Attribute
	// TemplatePolicy can adjust the driver-built secret template before explicit
	// SecretAttributes are merged.
	TemplatePolicy TemplatePolicy
	// MechanismOverride bypasses automatic standard-first mechanism selection.
	// Prefer automatic routing unless a module requires an unmodeled mechanism.
	MechanismOverride *uint
	// MechanismParameter is passed through to standard or vendor KEM
	// mechanisms. UnsafeParameter remains available for SDK structures that
	// are not yet represented by a typed raw parameter.
	MechanismParameter any
}

// KEMResult contains the encapsulation ciphertext and token-resident shared secret.
type KEMResult struct {
	// Ciphertext is the encapsulation value that must be sent to the holder of
	// the matching private key. It is copied into Go-owned memory.
	Ciphertext []byte
	// Secret references the token-resident shared-secret object. By default it is
	// a session object and remains usable only through the managed object flow.
	Secret ObjectRef
}

// kemSecretTemplate builds the vendor-neutral derived-secret template. KEM
// secrets default to session objects so a successful operation does not leave
// persistent key material unless the caller explicitly requests it.
func kemSecretTemplate(options KEMOptions) ([]*raw.Attribute, error) {
	policy := DefaultSecretKeyPolicy()
	policy.Token = false
	if options.SecretPolicy != nil {
		policy = *options.SecretPolicy
	}
	attributes := mergeAttributes(
		[]*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY),
			raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_GENERIC_SECRET),
			raw.NewAttribute(raw.CKA_VALUE_LEN, uint(32)),
			raw.NewAttribute(raw.CKA_DERIVE, true),
		},
		policyAttributes(policy, raw.CKO_SECRET_KEY),
		commonIdentity(options.Label, options.ID),
	)
	var err error
	attributes, err = applyTemplatePolicy(options.TemplatePolicy, TemplateContext{
		Operation: OperationEncapsulate, Algorithm: options.Algorithm,
		ObjectClass: raw.CKO_SECRET_KEY, KeyType: raw.CKK_GENERIC_SECRET,
		Label: options.Label, ID: options.ID,
	}, attributes)
	if err != nil {
		return nil, err
	}
	return mergeAttributes(attributes, options.SecretAttributes), nil
}

// Encapsulate creates a token-resident shared secret and returns the ciphertext for the peer. It
// prefers PKCS #11 3.2 C_EncapsulateKey, but a VendorModule may provide a compatible fallback.
func (c *Client) Encapsulate(ctx context.Context, publicKey ObjectRef, options KEMOptions) (KEMResult, error) {
	if options.Algorithm == "" {
		options.Algorithm = publicKey.Algorithm
	}
	route, err := c.Resolve(Intent{
		Operation: OperationEncapsulate, Algorithm: options.Algorithm,
		MechanismOverride:  options.MechanismOverride,
		MechanismParameter: options.MechanismParameter,
	})
	if err != nil {
		return KEMResult{}, err
	}
	template, err := kemSecretTemplate(options)
	if err != nil {
		return KEMResult{}, err
	}

	var result KEMResult
	err = c.withSession(ctx, sessionOptions{
		Operation: "encapsulate-key", ReadWrite: true,
	}, func(session *sessionLease) error {
		device := session.currentDevice()
		if device.vendor != nil {
			vendorResult, handled, hookErr := device.vendor.Encapsulate(
				ctx, session, publicKey, route, options, cloneAttributeTemplate(template),
			)
			if hookErr != nil {
				return hookErr
			}
			if handled {
				result = vendorResult
				return nil
			}
		}

		handle, resolveErr := session.Resolve(ctx, publicKey)
		if resolveErr != nil {
			return resolveErr
		}
		ciphertext, secret, callErr := session.EncapsulateKey(ctx,
			[]*raw.Mechanism{route.Mechanism}, handle, template,
		)
		if callErr != nil {
			session.MarkBroken()
			return callErr
		}
		result = KEMResult{
			Ciphertext: ciphertext,
			Secret: ObjectRef{
				Handle: secret, Class: raw.CKO_SECRET_KEY,
				KeyType: raw.CKK_GENERIC_SECRET,
				Label:   options.Label, ID: slices.Clone(options.ID),
			},
		}
		return nil
	})
	if err != nil {
		return KEMResult{}, err
	}
	return result, nil
}

// Decapsulate rebuilds a token-resident shared secret from ciphertext. It prefers PKCS #11 3.2
// C_DecapsulateKey, with an optional VendorModule fallback.
func (c *Client) Decapsulate(ctx context.Context, privateKey ObjectRef, ciphertext []byte, options KEMOptions) (ObjectRef, error) {
	if options.Algorithm == "" {
		options.Algorithm = privateKey.Algorithm
	}
	route, err := c.Resolve(Intent{
		Operation: OperationDecapsulate, Algorithm: options.Algorithm,
		MechanismOverride:  options.MechanismOverride,
		MechanismParameter: options.MechanismParameter,
	})
	if err != nil {
		return ObjectRef{}, err
	}
	template, err := kemSecretTemplate(options)
	if err != nil {
		return ObjectRef{}, err
	}

	var result ObjectRef
	err = c.withSession(ctx, sessionOptions{
		Operation: "decapsulate-key", ReadWrite: true,
	}, func(session *sessionLease) error {
		device := session.currentDevice()
		if device.vendor != nil {
			vendorResult, handled, hookErr := device.vendor.Decapsulate(
				ctx, session, privateKey, ciphertext, route, options,
				cloneAttributeTemplate(template),
			)
			if hookErr != nil {
				return hookErr
			}
			if handled {
				result = vendorResult
				return nil
			}
		}

		handle, resolveErr := session.Resolve(ctx, privateKey)
		if resolveErr != nil {
			return resolveErr
		}
		secret, callErr := session.DecapsulateKey(ctx,
			[]*raw.Mechanism{route.Mechanism}, handle, ciphertext, template,
		)
		if callErr != nil {
			session.MarkBroken()
			return callErr
		}
		result = ObjectRef{
			Handle: secret, Class: raw.CKO_SECRET_KEY,
			KeyType: raw.CKK_GENERIC_SECRET,
			Label:   options.Label, ID: slices.Clone(options.ID),
		}
		return nil
	})
	if err != nil {
		return ObjectRef{}, err
	}
	return result, nil
}

// ExportValue returns CKA_VALUE when the token allows it. This exports secret material into Go
// memory, so callers should keep the returned slice short-lived and overwrite it when practical.
// Any partial attribute error is preserved.
func (c *Client) ExportValue(ctx context.Context, object ObjectRef) ([]byte, error) {
	attributes, err := c.Attributes(ctx, object, raw.NewAttribute(raw.CKA_VALUE, nil))
	if err != nil && len(attributes) == 0 {
		return nil, err
	}
	if len(attributes) != 1 || attributes[0].Value == nil {
		return nil, errors.New("pkcs11: CKA_VALUE is unavailable or sensitive")
	}
	return attributes[0].Value, err
}
