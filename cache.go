package pkcs11

import (
	"slices"
	"sync"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// AttributeCachePolicy decides whether an attribute type may be retained in
// the managed cache. Returning true opts that type into caching. The default
// policy excludes key material, mutable stateful-signature counters, RNG seed
// material, and all vendor-defined attributes.
type AttributeCachePolicy func(attributeType uint) bool

// CacheConfig controls the bounded object-handle and attribute caches.
// Zero values select conservative defaults.
type CacheConfig struct {
	// ObjectTTL is the lifetime of cached object-search results. Zero selects the
	// default. Entries are also invalidated by module-generation changes.
	ObjectTTL time.Duration
	// AttributeTTL is the lifetime of cached attribute responses. Zero selects
	// the shorter conservative default.
	AttributeTTL time.Duration
	// ObjectMaxEntries bounds distinct object-search keys. Zero selects the
	// default; a negative value leaves the cache unbounded.
	ObjectMaxEntries int
	// AttributeMaxEntries bounds distinct object/request combinations. Zero
	// selects the default; a negative value leaves the cache unbounded.
	AttributeMaxEntries int
	// DisableObjects bypasses object-handle caching entirely.
	DisableObjects bool
	// DisableAttributes bypasses attribute caching entirely.
	DisableAttributes bool
	// AttributePolicy decides which attribute types are safe to retain. A nil
	// policy selects DefaultAttributeCachePolicy.
	AttributePolicy AttributeCachePolicy
}

// DefaultCacheConfig returns the standard cache sizes, lifetimes, and safe attribute policy.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		ObjectTTL:           30 * time.Second,
		AttributeTTL:        5 * time.Second,
		ObjectMaxEntries:    4096,
		AttributeMaxEntries: 4096,
		AttributePolicy:     DefaultAttributeCachePolicy,
	}
}

// DefaultAttributeCachePolicy permits ordinary public metadata and excludes
// values that can contain secret key material, volatile one-time state, or
// unclassified vendor data. Applications can supply a stricter or broader
// policy in CacheConfig when they understand their module's attributes.
func DefaultAttributeCachePolicy(attributeType uint) bool {
	if attributeType >= raw.CKA_VENDOR_DEFINED {
		return false
	}
	switch attributeType {
	case raw.CKA_VALUE,
		raw.CKA_PRIVATE_EXPONENT,
		raw.CKA_PRIME_1,
		raw.CKA_PRIME_2,
		raw.CKA_EXPONENT_1,
		raw.CKA_EXPONENT_2,
		raw.CKA_COEFFICIENT,
		raw.CKA_SEED,
		raw.CKA_OTP_COUNTER,
		raw.CKA_OTP_TIME,
		raw.CKA_HSS_KEYS_REMAINING:
		return false
	default:
		return true
	}
}

// cacheEntry stores an immutable defensive copy together with two independent
// invalidation dimensions: wall-clock expiry and module generation.
type cacheEntry[T any] struct {
	value      T
	expires    time.Time
	generation uint64
	lastAccess uint64
}

// tokenCache is a small, mutex-protected, approximate-LRU cache scoped to one
// selected token. It never returns its stored slices directly.
type tokenCache struct {
	config     CacheConfig
	mu         sync.Mutex
	sequence   uint64
	objects    map[string]cacheEntry[[]raw.ObjectHandle]
	refs       map[string]cacheEntry[[]ObjectRef]
	attributes map[string]cacheEntry[[]*raw.Attribute]
}

// newTokenCache applies conservative defaults and creates empty maps even when a
// cache class is disabled, keeping invalidation and diagnostics simple.
func newTokenCache(config CacheConfig) *tokenCache {
	defaults := DefaultCacheConfig()
	if config.ObjectTTL == 0 {
		config.ObjectTTL = defaults.ObjectTTL
	}
	if config.AttributeTTL == 0 {
		config.AttributeTTL = defaults.AttributeTTL
	}
	if config.ObjectMaxEntries == 0 {
		config.ObjectMaxEntries = defaults.ObjectMaxEntries
	}
	if config.AttributeMaxEntries == 0 {
		config.AttributeMaxEntries = defaults.AttributeMaxEntries
	}
	if config.AttributePolicy == nil {
		config.AttributePolicy = defaults.AttributePolicy
	}
	return &tokenCache{
		config:     config,
		objects:    make(map[string]cacheEntry[[]raw.ObjectHandle]),
		refs:       make(map[string]cacheEntry[[]ObjectRef]),
		attributes: make(map[string]cacheEntry[[]*raw.Attribute]),
	}
}

// invalidate drops all entries after any operation that may have changed token
// objects, attributes, sessions, or the selected module generation.
func (c *tokenCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.objects)
	clear(c.refs)
	clear(c.attributes)
	c.mu.Unlock()
}

// cloneHandles prevents callers from mutating a cached result slice.
func cloneHandles(v []raw.ObjectHandle) []raw.ObjectHandle {
	return slices.Clone(v)
}

// cloneAttributes recursively copies values and nested attribute templates so
// neither callers nor the raw layer can mutate cache-owned memory.
func cloneAttributes(v []*raw.Attribute) []*raw.Attribute {
	out := make([]*raw.Attribute, len(v))
	for i, a := range v {
		if a == nil {
			continue
		}
		out[i] = &raw.Attribute{Type: a.Type, Value: slices.Clone(a.Value)}
		if a.Children != nil {
			out[i].Children = cloneAttributes(a.Children)
		}
	}
	return out
}

// nextSequenceLocked advances the monotonic access counter used for approximate
// LRU eviction. c.mu must be held.
func (c *tokenCache) nextSequenceLocked() uint64 {
	c.sequence++
	return c.sequence
}

// attributesCacheable applies an all-or-nothing policy to an attribute request
// and all nested templates. Mixing one sensitive attribute into a request keeps
// the complete response out of cache, avoiding partial-result ambiguity.
func (c *tokenCache) attributesCacheable(attributes []*raw.Attribute) bool {
	if c == nil || c.config.DisableAttributes || len(attributes) == 0 {
		return false
	}
	for _, attribute := range attributes {
		// A nil attribute is malformed input and must not accidentally become a
		// cacheable wildcard.
		if attribute == nil || !c.config.AttributePolicy(attribute.Type) {
			return false
		}
		if len(attribute.Children) > 0 && !c.attributesCacheable(attribute.Children) {
			return false
		}
	}
	return true
}

// getObjects returns a defensive copy only when both TTL and module generation
// still match. Expired or stale entries are removed eagerly on lookup.
func (c *tokenCache) getObjects(key string, generation uint64) ([]raw.ObjectHandle, bool) {
	if c == nil || c.config.DisableObjects {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.objects[key]
	if !ok || entry.generation != generation || !now.Before(entry.expires) {
		if ok {
			delete(c.objects, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	entry.lastAccess = c.nextSequenceLocked()
	c.objects[key] = entry
	value := cloneHandles(entry.value)
	c.mu.Unlock()
	return value, true
}

// putObjects records a defensive copy and evicts the least recently accessed
// key when inserting beyond the configured bound.
func (c *tokenCache) putObjects(key string, generation uint64, value []raw.ObjectHandle) {
	if c == nil || c.config.DisableObjects || c.config.ObjectMaxEntries == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.pruneObjectsLocked(now)
	if _, exists := c.objects[key]; !exists {
		c.evictOldestObjectLocked()
	}
	c.objects[key] = cacheEntry[[]raw.ObjectHandle]{
		value:      cloneHandles(value),
		generation: generation,
		expires:    now.Add(c.config.ObjectTTL),
		lastAccess: c.nextSequenceLocked(),
	}
	c.mu.Unlock()
}

// getRefs returns cached find results under the same TTL and generation rules
// as object-handle lookups.
func (c *tokenCache) getRefs(key string, generation uint64) ([]ObjectRef, bool) {
	if c == nil || c.config.DisableObjects {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.refs[key]
	if !ok || entry.generation != generation || !now.Before(entry.expires) {
		if ok {
			delete(c.refs, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	entry.lastAccess = c.nextSequenceLocked()
	c.refs[key] = entry
	value := cloneObjectRefs(entry.value)
	c.mu.Unlock()
	return value, true
}

// putRefs records find results, bounded by the object-search limits.
func (c *tokenCache) putRefs(key string, generation uint64, value []ObjectRef) {
	if c == nil || c.config.DisableObjects || c.config.ObjectMaxEntries == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.pruneObjectsLocked(now)
	if _, exists := c.refs[key]; !exists {
		c.evictOldestRefLocked()
	}
	c.refs[key] = cacheEntry[[]ObjectRef]{
		value:      cloneObjectRefs(value),
		generation: generation,
		expires:    now.Add(c.config.ObjectTTL),
		lastAccess: c.nextSequenceLocked(),
	}
	c.mu.Unlock()
}

// cachedRefHandles scans cached find results for objects matching a locator.
// Unique id and class are matched when present; label/id constrain when set.
// Returns the distinct handles of every matching object.
func (c *tokenCache) cachedRefHandles(object ObjectRef, generation uint64) []raw.ObjectHandle {
	if c == nil || c.config.DisableObjects {
		return nil
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var handles []raw.ObjectHandle
	seen := make(map[raw.ObjectHandle]bool)
	add := func(ref ObjectRef, byUnique bool) {
		if ref.Handle == 0 || seen[ref.Handle] {
			return
		}
		if object.Class != 0 && ref.Class != object.Class {
			return
		}
		if byUnique {
			if ref.UniqueID != object.UniqueID {
				return
			}
		} else {
			if object.Label != "" && ref.Label != object.Label {
				return
			}
			if object.ID != nil && string(ref.ID) != string(object.ID) {
				return
			}
		}
		seen[ref.Handle] = true
		handles = append(handles, ref.Handle)
	}
	for _, entry := range c.refs {
		if entry.generation != generation || !now.Before(entry.expires) {
			continue
		}
		for _, ref := range entry.value {
			if object.UniqueID != "" {
				add(ref, true)
			} else {
				add(ref, false)
			}
		}
	}
	return handles
}

// cloneObjectRefs prevents callers from mutating cached find results.
func cloneObjectRefs(v []ObjectRef) []ObjectRef {
	out := make([]ObjectRef, len(v))
	for i, ref := range v {
		out[i] = ref
		out[i].ID = slices.Clone(ref.ID)
	}
	return out
}

// getAttributes returns a cached response only when the complete request is safe
// under the current AttributeCachePolicy.
func (c *tokenCache) getAttributes(key string, generation uint64, requested []*raw.Attribute) ([]*raw.Attribute, bool) {
	if !c.attributesCacheable(requested) {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.attributes[key]
	if !ok || entry.generation != generation || !now.Before(entry.expires) {
		if ok {
			delete(c.attributes, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	entry.lastAccess = c.nextSequenceLocked()
	c.attributes[key] = entry
	value := cloneAttributes(entry.value)
	c.mu.Unlock()
	return value, true
}

// putAttributes caches only when both the request and returned value are wholly
// cacheable. Checking the value protects against a module returning a nested or
// vendor-defined attribute that the request did not make obvious.
func (c *tokenCache) putAttributes(key string, generation uint64, requested, value []*raw.Attribute) {
	if !c.attributesCacheable(requested) || !c.attributesCacheable(value) || c.config.AttributeMaxEntries == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.pruneAttributesLocked(now)
	if _, exists := c.attributes[key]; !exists {
		c.evictOldestAttributeLocked()
	}
	c.attributes[key] = cacheEntry[[]*raw.Attribute]{
		value:      cloneAttributes(value),
		generation: generation,
		expires:    now.Add(c.config.AttributeTTL),
		lastAccess: c.nextSequenceLocked(),
	}
	c.mu.Unlock()
}

// pruneObjectsLocked removes expired object results. c.mu must be held.
func (c *tokenCache) pruneObjectsLocked(now time.Time) {
	for key, entry := range c.objects {
		if !now.Before(entry.expires) {
			delete(c.objects, key)
		}
	}
	for key, entry := range c.refs {
		if !now.Before(entry.expires) {
			delete(c.refs, key)
		}
	}
}

// pruneAttributesLocked removes expired attribute results. c.mu must be held.
func (c *tokenCache) pruneAttributesLocked(now time.Time) {
	for key, entry := range c.attributes {
		if !now.Before(entry.expires) {
			delete(c.attributes, key)
		}
	}
}

// evictOldestObjectLocked creates room for one insertion when the object cache
// is at capacity. A negative maximum means unbounded. c.mu must be held.
func (c *tokenCache) evictOldestObjectLocked() {
	maxEntries := c.config.ObjectMaxEntries
	if maxEntries < 0 || len(c.objects) < maxEntries {
		return
	}
	var oldestKey string
	var oldestAccess uint64
	first := true
	for key, entry := range c.objects {
		if first || entry.lastAccess < oldestAccess {
			oldestKey, oldestAccess, first = key, entry.lastAccess, false
		}
	}
	if !first {
		delete(c.objects, oldestKey)
	}
}

// evictOldestRefLocked creates room for one insertion when the find-result
// cache is at capacity. A negative maximum means unbounded. c.mu must be held.
func (c *tokenCache) evictOldestRefLocked() {
	maxEntries := c.config.ObjectMaxEntries
	if maxEntries < 0 || len(c.refs) < maxEntries {
		return
	}
	var oldestKey string
	var oldestAccess uint64
	first := true
	for key, entry := range c.refs {
		if first || entry.lastAccess < oldestAccess {
			oldestKey, oldestAccess, first = key, entry.lastAccess, false
		}
	}
	if !first {
		delete(c.refs, oldestKey)
	}
}

// evictOldestAttributeLocked creates room for one insertion when the attribute
// cache is at capacity. A negative maximum means unbounded. c.mu must be held.
func (c *tokenCache) evictOldestAttributeLocked() {
	maxEntries := c.config.AttributeMaxEntries
	if maxEntries < 0 || len(c.attributes) < maxEntries {
		return
	}
	var oldestKey string
	var oldestAccess uint64
	first := true
	for key, entry := range c.attributes {
		if first || entry.lastAccess < oldestAccess {
			oldestKey, oldestAccess, first = key, entry.lastAccess, false
		}
	}
	if !first {
		delete(c.attributes, oldestKey)
	}
}
