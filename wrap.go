package pkcs11

import (
	"context"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// WrapOptions controls standard or PKCS #11 3.2 authenticated key wrapping.
// Wrapping remains mechanism-explicit because wrapped-key formats are protocol
// choices and cannot be inferred safely from the key algorithms alone.
type WrapOptions struct {
	// Mechanism identifies the exact wrapping algorithm and parameter structure.
	// The driver still applies detected vendor parameter normalization.
	Mechanism *raw.Mechanism
	// AssociatedData is authenticated but not encrypted when Authenticated is
	// true. It is ignored by the conventional C_WrapKey path.
	AssociatedData []byte
	// Authenticated selects C_WrapKeyAuthenticated instead of C_WrapKey. The
	// selected module must expose the PKCS #11 3.2 function.
	Authenticated bool
}

// Wrap exports key in the wrapping format selected by options.Mechanism. The
// operation is intentionally not replayed: a remote HSM may have completed the
// wrap even when the client receives a transport or session error afterward.
func (c *Client) Wrap(ctx context.Context, wrappingKey, key ObjectRef, options WrapOptions) ([]byte, error) {
	if options.Mechanism == nil {
		return nil, fmt.Errorf("pkcs11: wrapping mechanism is required")
	}
	var wrapped []byte
	err := c.withSession(ctx, sessionOptions{Operation: "wrap-key"}, func(session *sessionLease) error {
		wrappingHandle, err := resolveObject(session, wrappingKey)
		if err != nil {
			return err
		}
		keyHandle, err := resolveObject(session, key)
		if err != nil {
			return err
		}
		// Resolve both durable references inside the same managed session because
		// object handles are session/module-generation scoped.
		if options.Authenticated {
			wrapped, err = session.WrapKeyAuthenticated([]*raw.Mechanism{options.Mechanism}, wrappingHandle, keyHandle, options.AssociatedData)
		} else {
			wrapped, err = session.WrapKey([]*raw.Mechanism{options.Mechanism}, wrappingHandle, keyHandle)
		}
		if err != nil {
			session.MarkBroken()
		}
		return err
	})
	return wrapped, err
}

// UnwrapOptions controls creation of a token or session object from wrapped key
// material. The caller supplies the object template because key policy, class,
// usage, and persistence cannot be recovered portably from every wrapping format.
type UnwrapOptions struct {
	// Mechanism identifies the exact unwrapping algorithm and parameters.
	Mechanism *raw.Mechanism
	// Attributes is the creation template passed to the token after vendor
	// normalization. It should include class, key type, policy, and usage fields.
	Attributes []*raw.Attribute
	// AssociatedData must match the value used by authenticated wrapping.
	AssociatedData []byte
	// Authenticated selects C_UnwrapKeyAuthenticated instead of C_UnwrapKey.
	Authenticated bool
	// Reference supplies durable metadata for the returned ObjectRef. Its Handle
	// is replaced with the newly created native handle.
	Reference ObjectRef
}

// Unwrap imports wrapped key material as a new token or session object. The
// operation is not replayed because a failed response may still have created an
// object in the HSM, and automatically repeating it could create duplicates.
func (c *Client) Unwrap(ctx context.Context, unwrappingKey ObjectRef, wrapped []byte, options UnwrapOptions) (ObjectRef, error) {
	if options.Mechanism == nil {
		return ObjectRef{}, fmt.Errorf("pkcs11: unwrapping mechanism is required")
	}
	var handle raw.ObjectHandle
	err := c.withSession(ctx, sessionOptions{Operation: "unwrap-key", ReadWrite: true}, func(session *sessionLease) error {
		unwrappingHandle, err := resolveObject(session, unwrappingKey)
		if err != nil {
			return err
		}
		if options.Authenticated {
			handle, err = session.UnwrapKeyAuthenticated([]*raw.Mechanism{options.Mechanism}, unwrappingHandle, wrapped, options.Attributes, options.AssociatedData)
		} else {
			handle, err = session.UnwrapKey([]*raw.Mechanism{options.Mechanism}, unwrappingHandle, wrapped, options.Attributes)
		}
		if err != nil {
			session.MarkBroken()
		}
		return err
	})
	if err != nil {
		return ObjectRef{}, err
	}
	// Preserve the caller's class, key type, algorithm, and durable locators while
	// replacing only the transient handle returned by this operation.
	result := options.Reference
	result.Handle = handle
	return result, nil
}
