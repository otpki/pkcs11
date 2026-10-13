package pkcs11

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// ObjectQuery selects token or session objects by stable PKCS #11 attributes.
type ObjectQuery struct {
	// Class matches CKA_CLASS. Nil leaves the object class unconstrained.
	Class *uint
	// KeyType matches CKA_KEY_TYPE. Nil leaves the key type unconstrained.
	KeyType *uint
	// UniqueID matches CKA_UNIQUE_ID.
	UniqueID string
	// Label matches CKA_LABEL.
	Label string
	// ID matches the opaque CKA_ID byte string.
	ID []byte
	// Token matches CKA_TOKEN. Nil includes token and session objects.
	Token *bool
	// Private matches CKA_PRIVATE. Nil includes public and private objects.
	Private *bool
	// Limit bounds returned references after object discovery. Zero means unlimited.
	Limit int
}

// ObjectInfo combines a resolved reference with common policy attributes.
type ObjectInfo struct {
	// ObjectRef identifies the object and carries any inferred algorithm metadata.
	ObjectRef
	// Token is the decoded CKA_TOKEN policy bit.
	Token bool
	// Private is the decoded CKA_PRIVATE policy bit.
	Private bool
	// Modifiable is the decoded CKA_MODIFIABLE policy bit.
	Modifiable bool
	// Extractable is the decoded CKA_EXTRACTABLE policy bit when applicable.
	Extractable bool
	// Attributes contains the raw values used to build this snapshot.
	Attributes []*raw.Attribute
}

// queryCacheKey uses explicit delimiters and hexadecimal byte encoding so labels,
// IDs, and zero values cannot collide in the object-search cache namespace.
func queryCacheKey(query ObjectQuery) string {
	var b strings.Builder
	b.WriteString("query")
	if query.Class != nil {
		b.WriteString(";class=")
		b.WriteString(strconv.FormatUint(uint64(*query.Class), 16))
	}
	if query.KeyType != nil {
		b.WriteString(";keytype=")
		b.WriteString(strconv.FormatUint(uint64(*query.KeyType), 16))
	}
	if query.UniqueID != "" {
		b.WriteString(";unique-id=")
		b.WriteString(hex.EncodeToString([]byte(query.UniqueID)))
	}
	if query.Label != "" {
		b.WriteString(";label=")
		b.WriteString(hex.EncodeToString([]byte(query.Label)))
	}
	if query.ID != nil {
		b.WriteString(";id=")
		b.WriteString(hex.EncodeToString(query.ID))
	}
	if query.Token != nil {
		b.WriteString(";token=")
		b.WriteString(strconv.FormatBool(*query.Token))
	}
	if query.Private != nil {
		b.WriteString(";private=")
		b.WriteString(strconv.FormatBool(*query.Private))
	}
	return b.String()
}

func sameObjectRef(left, right ObjectRef) bool {
	if left.Handle != 0 && right.Handle != 0 && left.Handle == right.Handle {
		return true
	}
	if left.UniqueID != "" && left.UniqueID == right.UniqueID {
		return true
	}
	if left.ID != nil && right.ID != nil && string(left.ID) == string(right.ID) && left.Class == right.Class {
		return true
	}
	return false
}

func objectCacheKey(object ObjectRef) string {
	var b strings.Builder
	b.WriteString("object")
	b.WriteString(";handle=")
	b.WriteString(strconv.FormatUint(uint64(object.Handle), 16))
	b.WriteString(";class=")
	b.WriteString(strconv.FormatUint(uint64(object.Class), 16))
	b.WriteString(";keytype=")
	b.WriteString(strconv.FormatUint(uint64(object.KeyType), 16))
	b.WriteString(";unique-id=")
	b.WriteString(hex.EncodeToString([]byte(object.UniqueID)))
	b.WriteString(";label=")
	b.WriteString(hex.EncodeToString([]byte(object.Label)))
	b.WriteString(";id=")
	b.WriteString(hex.EncodeToString(object.ID))
	return b.String()
}

func attributeCacheKey(object ObjectRef, requested []*raw.Attribute) string {
	var b strings.Builder
	b.WriteString(objectCacheKey(object))
	b.WriteString(";attributes=")
	for i, attribute := range requested {
		if i > 0 {
			b.WriteByte(',')
		}
		if attribute == nil {
			b.WriteString("nil")
			continue
		}
		b.WriteString(strconv.FormatUint(uint64(attribute.Type), 16))
	}
	return b.String()
}

func queryTemplate(query ObjectQuery) []*raw.Attribute {
	var attributes []*raw.Attribute
	if query.Class != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_CLASS, *query.Class))
	}
	if query.KeyType != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_KEY_TYPE, *query.KeyType))
	}
	if query.UniqueID != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_UNIQUE_ID, query.UniqueID))
	}
	if query.Label != "" {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_LABEL, query.Label))
	}
	if query.ID != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_ID, query.ID))
	}
	if query.Token != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_TOKEN, *query.Token))
	}
	if query.Private != nil {
		attributes = append(attributes, raw.NewAttribute(raw.CKA_PRIVATE, *query.Private))
	}
	return attributes
}

// Find returns every object matching query, up to Query.Limit when nonzero.
func (c *Client) Find(ctx context.Context, query ObjectQuery) ([]ObjectRef, error) {
	var result []ObjectRef
	err := c.withSession(ctx, sessionOptions{Operation: "find-objects", Idempotent: true}, func(session *sessionLease) error {
		key := queryCacheKey(query)
		refsKey := key + ";limit=" + strconv.Itoa(query.Limit)
		if refs, ok := c.cache.getRefs(refsKey, session.generation); ok {
			result = refs
			return nil
		}
		handles, ok := c.cache.getObjects(key, session.generation)
		if !ok {
			var err error
			handles, err = session.FindAllObjects(ctx, queryTemplate(query), 64)
			if err != nil {
				return err
			}
			c.cache.putObjects(key, session.generation, handles)
		}
		if query.Limit > 0 && len(handles) > query.Limit {
			handles = handles[:query.Limit]
		}
		requested := []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, nil), raw.NewAttribute(raw.CKA_KEY_TYPE, nil),
			raw.NewAttribute(raw.CKA_UNIQUE_ID, nil),
			raw.NewAttribute(raw.CKA_LABEL, nil), raw.NewAttribute(raw.CKA_ID, nil),
			raw.NewAttribute(raw.CKA_PARAMETER_SET, nil), raw.NewAttribute(raw.CKA_EC_PARAMS, nil),
			raw.NewAttribute(raw.CKA_VALUE_LEN, nil), raw.NewAttribute(raw.CKA_MODULUS_BITS, nil),
		}
		device := session.currentDevice()
		if device.vendor != nil {
			for _, attributeType := range device.vendor.ObjectAttributes() {
				requested = append(requested, raw.NewAttribute(attributeType, nil))
			}
		}
		requested = mergeAttributes(requested)
		allAttributes := make([][]*raw.Attribute, len(handles))
		err := session.call(ctx, "C_GetAttributeValue", func(module raw.Module) error {
			if reader, ok := module.(multiAttributeReader); ok {
				values, errs, readErr := reader.GetAttributeValues(session.handle, handles, requested)
				if readErr != nil {
					return readErr
				}
				for i := range values {
					if errs[i] != nil && len(values[i]) == 0 {
						return errs[i]
					}
				}
				copy(allAttributes, values)
				return nil
			}
			for i, handle := range handles {
				// GetAttributeValue fills the template in place, so each handle
				// reads through its own copy.
				attributes, attributeErr := module.GetAttributeValue(session.handle, handle, cloneAttributeTemplate(requested))
				if attributeErr != nil && len(attributes) == 0 {
					// Utimaco's CXI layer answers a batched read with a device
					// error when any property tag is unknown instead of
					// reporting per-attribute failures, so retry
					// attribute-by-attribute before giving up on the object.
					attributes, attributeErr = readObjectAttributes(module, session.handle, handle, requested)
					if attributeErr != nil && len(attributes) == 0 {
						return attributeErr
					}
				}
				allAttributes[i] = attributes
			}
			return nil
		})
		if err != nil {
			return err
		}
		for i, handle := range handles {
			ref := ObjectRef{Handle: handle}
			for _, attribute := range allAttributes[i] {
				switch attribute.Type {
				case raw.CKA_CLASS:
					ref.Class, _ = raw.ULong(attribute.Value)
				case raw.CKA_KEY_TYPE:
					ref.KeyType, _ = raw.ULong(attribute.Value)
				case raw.CKA_UNIQUE_ID:
					ref.UniqueID = string(attribute.Value)
				case raw.CKA_LABEL:
					ref.Label = string(attribute.Value)
				case raw.CKA_ID:
					ref.ID = slices.Clone(attribute.Value)
				case raw.CKA_MODULUS_BITS:
					ref.ModulusBits, _ = raw.ULong(attribute.Value)
				}
			}
			ref.Algorithm = inferAlgorithm(device, ref.KeyType, allAttributes[i])
			result = append(result, ref)
		}
		c.cache.putRefs(refsKey, session.generation, result)
		return nil
	})
	return result, err
}

// multiAttributeReader reads one attribute template for many objects in a
// single module operation. Proxy transports implement it to collapse the
// per-object attribute sweep into a handful of round-trips; direct modules
// use the per-handle path.
type multiAttributeReader interface {
	GetAttributeValues(session raw.SessionHandle, objects []raw.ObjectHandle, template []*raw.Attribute) ([][]*raw.Attribute, []error, error)
}

// readObjectAttributes retries a failed batched attribute query one attribute
// at a time. Providers that hard-fail a multi-attribute read on any unknown
// property tag still answer each attribute separately under the ordinary
// per-attribute error model.
func readObjectAttributes(module raw.Module, session raw.SessionHandle, handle raw.ObjectHandle, requested []*raw.Attribute) ([]*raw.Attribute, error) {
	var collected []*raw.Attribute
	var firstErr error
	for _, attribute := range requested {
		values, err := module.GetAttributeValue(session, handle, cloneAttributeTemplate([]*raw.Attribute{attribute}))
		collected = append(collected, values...)
		if len(values) == 0 && firstErr == nil {
			firstErr = err
		}
	}
	if len(collected) == 0 {
		return nil, firstErr
	}
	return collected, nil
}

// inferAlgorithm converts token metadata back into the public algorithm model.
// It is deliberately best effort: an empty result means the object remains fully
// usable through raw attributes or explicit algorithm options.
func inferAlgorithm(device Device, keyType uint, attributes []*raw.Attribute) Algorithm {
	// Let the selected vendor module interpret proprietary key types and metadata
	// before the generic standard decoder runs. This keeps private attributes and
	// encoding heuristics out of the root package.
	if device.vendor != nil {
		if algorithm, ok := device.vendor.InferAlgorithm(VendorObjectMetadata{
			Device: cloneDevice(device), KeyType: keyType, Attributes: cloneAttributeTemplate(attributes),
		}); ok {
			return algorithm
		}
	}

	parameterSet := uint(0)
	valueLength := uint(0)
	var ecParameters []byte
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}
		switch attribute.Type {
		case raw.CKA_PARAMETER_SET:
			parameterSet, _ = raw.ULong(attribute.Value)
		case raw.CKA_VALUE_LEN:
			valueLength, _ = raw.ULong(attribute.Value)
		case raw.CKA_EC_PARAMS:
			ecParameters = attribute.Value
		}
	}
	switch keyType {
	case raw.CKK_RSA:
		return AlgorithmRSA
	case raw.CKK_EC:
		switch curveIdentifier(ecParameters) {
		case "1.2.840.10045.3.1.7", "prime256v1", "secp256r1", "p-256":
			return AlgorithmECDSAP256
		case "1.3.132.0.34", "secp384r1", "p-384":
			return AlgorithmECDSAP384
		case "1.3.132.0.35", "secp521r1", "p-521":
			return AlgorithmECDSAP521
		}
	case raw.CKK_EC_EDWARDS:
		switch curveIdentifier(ecParameters) {
		case "1.3.101.112", "ed25519", "edwards25519":
			return AlgorithmEd25519
		case "1.3.101.113", "ed448", "edwards448":
			return AlgorithmEd448
		}
	case raw.CKK_EC_MONTGOMERY:
		switch curveIdentifier(ecParameters) {
		case "1.3.101.110", "x25519", "curve25519":
			return AlgorithmX25519
		case "1.3.101.111", "x448", "curve448":
			return AlgorithmX448
		}
	case raw.CKK_DSA:
		return AlgorithmDSA
	case raw.CKK_DH:
		return AlgorithmDH
	case raw.CKK_HSS:
		return AlgorithmHSS
	case raw.CKK_XMSS:
		return AlgorithmXMSS
	case raw.CKK_XMSSMT:
		return AlgorithmXMSSMT
	case raw.CKK_AES:
		switch valueLength {
		case 16:
			return AlgorithmAES128
		case 24:
			return AlgorithmAES192
		case 32:
			return AlgorithmAES256
		}
	case raw.CKK_CHACHA20:
		return AlgorithmChaCha20
	case raw.CKK_SHA256_HMAC:
		return AlgorithmHMACSHA256
	case raw.CKK_SHA384_HMAC:
		return AlgorithmHMACSHA384
	case raw.CKK_SHA512_HMAC:
		return AlgorithmHMACSHA512
	case raw.CKK_ML_DSA:
		switch parameterSet {
		case raw.CKP_ML_DSA_44:
			return AlgorithmMLDSA44
		case raw.CKP_ML_DSA_65:
			return AlgorithmMLDSA65
		case raw.CKP_ML_DSA_87:
			return AlgorithmMLDSA87
		}
	case raw.CKK_ML_KEM:
		switch parameterSet {
		case raw.CKP_ML_KEM_512:
			return AlgorithmMLKEM512
		case raw.CKP_ML_KEM_768:
			return AlgorithmMLKEM768
		case raw.CKP_ML_KEM_1024:
			return AlgorithmMLKEM1024
		}
	case raw.CKK_SLH_DSA:
		for algorithm, expected := range map[Algorithm]uint{
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
			if parameterSet == expected {
				return algorithm
			}
		}
	}

	// Vendor modules frequently retain legacy key-type identifiers after the
	// standardized algorithm is available. Resolve those aliases using the
	// selected adapter and, where applicable, CKA_PARAMETER_SET.
	for _, algorithm := range AllAlgorithms() {
		spec := algorithmSpecs[algorithm]
		id, ok := device.definition.identifiers.keyTypes[normalizeAlias(spec.KeyTypeAlias)]
		if !ok || uint(id) != keyType {
			continue
		}
		if spec.ParameterSetAlias != "" {
			expected := spec.ParameterSet
			if value, exists := device.definition.identifiers.parameterSets[normalizeAlias(spec.ParameterSetAlias)]; exists {
				expected = uint(value)
			}
			if expected != 0 && parameterSet != expected {
				continue
			}
		}
		return algorithm
	}
	return ""
}

func curveIdentifier(value []byte) string {
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(value, &oid); err == nil && len(rest) == 0 {
		return oid.String()
	}
	var name string
	if rest, err := asn1.Unmarshal(value, &name); err == nil && len(rest) == 0 {
		return strings.ToLower(strings.TrimSpace(name))
	}
	return strings.ToLower(strings.TrimSpace(strings.Trim(string(value), "\x00")))
}

// resolveObject prefers durable locators over a cached native handle. Handles are
// scoped to a module/session generation and can become invalid after reconnect,
// failover, token replacement, or provider-specific session behavior.
func resolveObject(ctx context.Context, session *sessionLease, object ObjectRef) (raw.ObjectHandle, error) {
	if object.ID == nil && object.Label == "" && object.UniqueID == "" {
		if object.Handle == 0 {
			return 0, errors.New("pkcs11: object has neither handle nor locator")
		}
		return object.Handle, nil
	}
	class, keyType := object.Class, object.KeyType
	var classPtr *uint
	if class != 0 {
		classPtr = &class
	}
	// Locator ladder, most preferred first. CKA_UNIQUE_ID identifies the
	// object on its own — AND-ing Label/ID/KeyType only adds miss paths —
	// but some providers (utimaco QP) reject the attribute in a find
	// template outright, so a failed or empty unique query falls through
	// to the classic label/id template. KeyType joins last: vendors whose
	// CKK values are unmatchable (utimaco's 0x8000xxxx) must not let it
	// shrink a working query to zero hits.
	queries := []ObjectQuery{}
	if object.UniqueID != "" {
		queries = append(queries, ObjectQuery{
			UniqueID: object.UniqueID, Class: classPtr, Limit: 2,
		})
	}
	if object.Label != "" || object.ID != nil {
		queries = append(queries, ObjectQuery{
			Label: object.Label, ID: object.ID, Class: classPtr, Limit: 2,
		})
	}
	if len(queries) == 0 {
		return 0, errors.New("pkcs11: object has neither handle nor locator")
	}
	locator := objectLocatorDescription(object)
	// A recent Find already recorded this generation's objects: hit it before
	// paying for another enumeration — remote backends can charge seconds per
	// find. Cached handles carry the same cross-session trust the objects
	// cache already applies.
	if session.pool != nil && session.pool.owner != nil {
		cached := session.pool.owner.cache.cachedRefHandles(object, session.generation)
		if len(cached) == 1 {
			return cached[0], nil
		}
		if len(cached) > 1 {
			return 0, fmt.Errorf("pkcs11: object locator %s is ambiguous (%d matches)", locator, len(cached))
		}
	}
	var firstErr error
	for _, query := range queries {
		key := queryCacheKey(query)
		var handles []raw.ObjectHandle
		var ok bool
		if session.pool != nil && session.pool.owner != nil {
			handles, ok = session.pool.owner.cache.getObjects(key, session.generation)
		}
		if !ok {
			// Ask for more than one result so a non-unique locator fails loudly
			// instead of selecting whichever handle the provider enumerates first.
			var err error
			handles, err = session.FindAllObjects(ctx, queryTemplate(query), 8)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if session.pool != nil && session.pool.owner != nil {
				session.pool.owner.cache.putObjects(key, session.generation, handles)
			}
		}
		if len(handles) == 0 {
			continue
		}
		if len(handles) > 1 && keyType != 0 {
			// Ambiguous: retry once with the key type constraint to split
			// same-label/id objects. Providers that cannot compare vendor
			// CKK values return empty here — the ambiguity error stands.
			narrowed, nerr := session.FindAllObjects(ctx,
				mergeAttributes(queryTemplate(query),
					[]*raw.Attribute{raw.NewAttribute(raw.CKA_KEY_TYPE, keyType)}), 8)
			if nerr == nil && len(narrowed) == 1 {
				handles = narrowed
			}
		}
		if len(handles) > 1 {
			return 0, fmt.Errorf("pkcs11: object locator %s is ambiguous (%d matches)", locator, len(handles))
		}
		return handles[0], nil
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return 0, fmt.Errorf("pkcs11: object %s was not found in current session", locator)
}

func objectLocatorDescription(object ObjectRef) string {
	switch {
	case object.UniqueID != "":
		return fmt.Sprintf("with CKA_UNIQUE_ID %q", object.UniqueID)
	case object.ID != nil:
		return fmt.Sprintf("with CKA_ID %x", object.ID)
	case object.Label != "":
		return fmt.Sprintf("with CKA_LABEL %q", object.Label)
	case object.Handle != 0:
		return fmt.Sprintf("with handle %#x", uint(object.Handle))
	default:
		return "without a locator"
	}
}

// Attributes reads the requested attributes, using the safe managed cache when eligible.
// The returned slice may contain successful values together with a non-nil error
// when a provider reports mixed per-attribute results.
func (c *Client) Attributes(ctx context.Context, object ObjectRef, requested ...*raw.Attribute) ([]*raw.Attribute, error) {
	var result []*raw.Attribute
	err := c.withSession(ctx, sessionOptions{Operation: "get-attributes", Idempotent: true}, func(session *sessionLease) error {
		cacheKey := attributeCacheKey(object, requested)
		if cached, ok := c.cache.getAttributes(cacheKey, session.generation, requested); ok {
			result = cached
			return nil
		}
		handle, err := resolveObject(ctx, session, object)
		if err != nil {
			return err
		}
		result, err = session.GetAttributeValue(ctx, handle, requested)
		if err == nil {
			c.cache.putAttributes(cacheKey, session.generation, requested, result)
		}
		return err
	})
	return result, err
}

// SetAttributes modifies object attributes and invalidates dependent caches.
// Attribute mutation is not retried because a transport failure can occur after
// the provider has committed the change.
func (c *Client) SetAttributes(ctx context.Context, object ObjectRef, attributes ...*raw.Attribute) error {
	return c.withSession(ctx, sessionOptions{Operation: "set-attributes", ReadWrite: true}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, object)
		if err != nil {
			return err
		}
		return session.SetAttributeValue(ctx, handle, attributes)
	})
}

// Destroy removes an object from the token and invalidates dependent caches.
// Destruction is intentionally not retried: success followed by a lost response
// is indistinguishable from a failure before the object was removed.
func (c *Client) Destroy(ctx context.Context, object ObjectRef) error {
	return c.withSession(ctx, sessionOptions{Operation: "destroy-object", ReadWrite: true}, func(session *sessionLease) error {
		handle, err := resolveObject(ctx, session, object)
		if err != nil {
			return err
		}
		return session.DestroyObject(ctx, handle)
	})
}
