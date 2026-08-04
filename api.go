package pkcs11

import (
	"context"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// KeyLocator identifies both halves of a key pair using durable PKCS #11
// attributes. ID is preferred because labels are commonly operator-visible and
// therefore not guaranteed to be unique.
type KeyLocator struct {
	// ID matches CKA_ID and is the preferred portable association between public,
	// private, and certificate objects.
	ID []byte
	// Label matches CKA_LABEL. Use it only when the deployment guarantees uniqueness.
	Label string
	// Algorithm constrains interpretation of the located objects. It is required
	// for vendor representations whose key type alone is ambiguous.
	Algorithm Algorithm
}

// Signer returns a crypto.Signer backed by an existing private key. Public-key
// material is loaded from config.Public when supplied, or from the matching
// public object when the private reference has a durable ID or label.
func (c *Client) Signer(ctx context.Context, config SignerConfig) (*Signer, error) {
	return newSigner(ctx, c, config)
}

// Decrypter returns a crypto.Decrypter backed by an existing private key.
func (c *Client) Decrypter(ctx context.Context, private, public ObjectRef) (*Decrypter, error) {
	return newDecrypter(ctx, c, private, public)
}

// FindOne requires exactly one matching object. It asks the token for at most
// two matches so ambiguous labels or IDs are reported instead of silently
// selecting an arbitrary object.
func (c *Client) FindOne(ctx context.Context, query ObjectQuery) (ObjectRef, error) {
	query.Limit = 2
	objects, err := c.Find(ctx, query)
	if err != nil {
		return ObjectRef{}, err
	}
	switch len(objects) {
	case 0:
		return ObjectRef{}, fmt.Errorf("pkcs11: no object matches query")
	case 1:
		return objects[0], nil
	default:
		return ObjectRef{}, fmt.Errorf("pkcs11: object query is ambiguous (%d matches)", len(objects))
	}
}

// FindKeyPair resolves public and private objects that share a CKA_ID or label.
// When the private object exposes CKA_ID, that ID is preferred for the public
// lookup even when the caller initially supplied only a label.
func (c *Client) FindKeyPair(ctx context.Context, locator KeyLocator) (KeyPair, error) {
	// A vendor module may describe a logical key pair that is represented by one
	// native object. The root package applies that model generically; it does not
	// need to know which provider or algorithm introduced it.
	if locator.Algorithm != "" {
		device := c.currentDevice()
		if device.vendor != nil {
			model, ok := device.vendor.KeyPairModel(locator.Algorithm, Route{Intent: Intent{Algorithm: locator.Algorithm}})
			if ok && model.SingleObject {
				class, keyType := model.ObjectClass, model.KeyType
				query := ObjectQuery{Label: locator.Label, ID: locator.ID}
				if class != 0 {
					query.Class = &class
				}
				if keyType != 0 {
					query.KeyType = &keyType
				}
				object, err := c.FindOne(ctx, query)
				if err != nil {
					return KeyPair{}, fmt.Errorf("pkcs11: find %s key using vendor model %q: %w", locator.Algorithm, device.Adapter.Name, err)
				}
				object.Algorithm = locator.Algorithm
				return KeyPair{Public: object, Private: object}, nil
			}
		}
	}
	privateClass := uint(raw.CKO_PRIVATE_KEY)
	private, err := c.FindOne(ctx, ObjectQuery{
		Class: &privateClass,
		Label: locator.Label,
		ID:    locator.ID,
	})
	if err != nil {
		return KeyPair{}, fmt.Errorf("pkcs11: find private key: %w", err)
	}
	if locator.Algorithm != "" && private.Algorithm != "" && private.Algorithm != locator.Algorithm {
		return KeyPair{}, fmt.Errorf("pkcs11: private key algorithm %q does not match requested %q", private.Algorithm, locator.Algorithm)
	}
	algorithm := locator.Algorithm
	if algorithm == "" {
		algorithm = private.Algorithm
	}
	publicClass := uint(raw.CKO_PUBLIC_KEY)
	// Tokens commonly populate CKA_ID on the private object even when lookup began
	// with a label. Reuse the discovered ID to avoid selecting a same-label public key.
	publicID := locator.ID
	if publicID == nil {
		publicID = private.ID
	}
	public, err := c.FindOne(ctx, ObjectQuery{
		Class: &publicClass,
		Label: locator.Label,
		ID:    publicID,
	})
	if err != nil {
		return KeyPair{}, fmt.Errorf("pkcs11: find public key: %w", err)
	}
	private.Algorithm = algorithm
	public.Algorithm = algorithm
	return KeyPair{Public: public, Private: private}, nil
}

// SignerFor resolves a key pair and constructs a signer in one operation.
func (c *Client) SignerFor(ctx context.Context, locator KeyLocator, config SignerConfig) (*Signer, error) {
	pair, err := c.FindKeyPair(ctx, locator)
	if err != nil {
		return nil, err
	}
	config.Private = pair.Private
	config.Public = pair.Public
	if config.Algorithm == "" {
		config.Algorithm = pair.Private.Algorithm
	}
	return c.Signer(ctx, config)
}

// DecrypterFor resolves an RSA key pair and constructs a decrypter.
func (c *Client) DecrypterFor(ctx context.Context, locator KeyLocator) (*Decrypter, error) {
	if locator.Algorithm == "" {
		locator.Algorithm = AlgorithmRSA
	}
	pair, err := c.FindKeyPair(ctx, locator)
	if err != nil {
		return nil, err
	}
	return c.Decrypter(ctx, pair.Private, pair.Public)
}
