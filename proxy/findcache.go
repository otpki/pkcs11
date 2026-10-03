package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// findCacheDefaultTTL bounds native enumeration reuse when the target does not
// configure one. Mutations invalidate immediately; the TTL only bounds drift
// from changes made outside this module (other applications on the same HSM).
const (
	findCacheDefaultTTL = 15 * time.Second
	// This is an optimization, not an object store. Stop caching before a
	// client with many different search templates can retain unlimited data.
	findCacheMaxEntries = 256
	findCacheMaxHandles = 4096
)

// findCacheKey identifies one enumeration within one native session. Handles
// are session-scoped on some providers, so results never cross sessions.
type findCacheKey struct {
	session  raw.SessionHandle
	template [16]byte
}

type findCacheEntry struct {
	handles    []raw.ObjectHandle
	generation uint64
	expires    time.Time
}

// pendingFind is one open search. Only a successful, fully read native search
// can become a cache entry. replay is separate from cached because an empty
// result is still a valid cache hit.
type pendingFind struct {
	key         findCacheKey
	generation  uint64
	replay      bool
	cached      []raw.ObjectHandle
	position    int
	recorded    []raw.ObjectHandle
	complete    bool
	uncacheable bool
}

// findCachingModule saves repeated HSM searches within the same native session.
// Some HSMs make each search a network round trip, so repeating one can be costly.
// Local changes clear saved results. The TTL limits how long changes made by
// another application can go unnoticed.
type findCachingModule struct {
	raw.Module
	ttl        time.Duration
	mu         sync.Mutex
	generation uint64
	entries    map[findCacheKey]findCacheEntry
	pending    map[raw.SessionHandle]*pendingFind
}

func newFindCachingModule(module raw.Module, ttl time.Duration) *findCachingModule {
	return &findCachingModule{
		Module:  module,
		ttl:     ttl,
		entries: make(map[findCacheKey]findCacheEntry),
		pending: make(map[raw.SessionHandle]*pendingFind),
	}
}

// findCacheModuleSource decorates every module produced by the inner source.
type findCacheModuleSource struct {
	inner pkcs11.ModuleSource
	ttl   time.Duration
}

func (s findCacheModuleSource) OpenModule(ctx context.Context) (raw.Module, error) {
	module, err := s.inner.OpenModule(ctx)
	if err != nil || module == nil {
		return module, err
	}
	return newFindCachingModule(module, s.ttl), nil
}

// RegistryKey keeps routes on the same underlying module instance. Routes that
// share a module must use the same cache policy.
func (s findCacheModuleSource) RegistryKey() string { return s.inner.RegistryKey() }
func (s findCacheModuleSource) String() string      { return s.inner.String() }

// findTemplateHash canonicalizes a search template. Attribute order does not
// affect matching semantics, so the hash sorts by attribute type.
func findTemplateHash(attributes []*raw.Attribute) [16]byte {
	type pair struct {
		kind  uint
		value []byte
	}
	pairs := make([]pair, 0, len(attributes))
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}
		pairs = append(pairs, pair{kind: attribute.Type, value: attribute.Value})
	}
	slices.SortFunc(pairs, func(a, b pair) int {
		switch {
		case a.kind < b.kind:
			return -1
		case a.kind > b.kind:
			return 1
		}
		return 0
	})
	digest := sha256.New()
	var scratch [8]byte
	for _, item := range pairs {
		binary.BigEndian.PutUint64(scratch[:], uint64(item.kind))
		digest.Write(scratch[:])
		binary.BigEndian.PutUint64(scratch[:], uint64(len(item.value)))
		digest.Write(scratch[:])
		digest.Write(item.value)
	}
	var sum [16]byte
	copy(sum[:], digest.Sum(nil))
	return sum
}

// invalidate clears saved results, not searches already in progress. A replay
// has no native search to fall back to, so its snapshot must live until Final.
func (m *findCachingModule) invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generation++
	clear(m.entries)
}

// FindObjectsInit reuses a complete cached search or starts a native search.
// One native session can have only one search open at a time.
func (m *findCachingModule) FindObjectsInit(session raw.SessionHandle, attributes []*raw.Attribute) error {
	key := findCacheKey{session: session, template: findTemplateHash(attributes)}
	m.mu.Lock()
	if _, busy := m.pending[session]; busy {
		m.mu.Unlock()
		return raw.Error(raw.CKR_OPERATION_ACTIVE)
	}
	if entry, ok := m.entries[key]; ok {
		if entry.generation == m.generation && time.Now().Before(entry.expires) {
			m.pending[session] = &pendingFind{
				key: key, generation: entry.generation, replay: true,
				cached: slices.Clone(entry.handles),
			}
			m.mu.Unlock()
			return nil
		}
		delete(m.entries, key)
	}
	pending := &pendingFind{key: key, generation: m.generation}
	m.pending[session] = pending
	m.mu.Unlock()

	if err := m.Module.FindObjectsInit(session, attributes); err != nil {
		m.mu.Lock()
		if m.pending[session] == pending {
			delete(m.pending, session)
		}
		m.mu.Unlock()
		return err
	}
	return nil
}

// FindObjects reads the next batch. Large searches still work, but stop being
// recorded once they exceed the cache's handle limit.
func (m *findCachingModule) FindObjects(session raw.SessionHandle, maxObjects int) ([]raw.ObjectHandle, bool, error) {
	if maxObjects < 1 {
		return nil, false, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	m.mu.Lock()
	pending, active := m.pending[session]
	if active && pending.replay {
		// Clamp before adding so an extremely large caller-supplied count
		// cannot overflow the slice index.
		count := min(maxObjects, len(pending.cached)-pending.position)
		end := pending.position + count
		batch := slices.Clone(pending.cached[pending.position:end])
		pending.position = end
		m.mu.Unlock()
		return batch, count == maxObjects, nil
	}
	m.mu.Unlock()

	batch, more, err := m.Module.FindObjects(session, maxObjects)
	if active {
		m.mu.Lock()
		if err != nil || len(batch) > findCacheMaxHandles-len(pending.recorded) {
			pending.uncacheable = true
			pending.recorded = nil
		}
		if !pending.uncacheable {
			pending.recorded = append(pending.recorded, batch...)
			pending.complete = !more || len(batch) == 0
		}
		m.mu.Unlock()
	}
	return batch, more, err
}

// FindObjectsFinal ends the search. Ending early is valid, but an unfinished
// result must not replace a later full search.
func (m *findCachingModule) FindObjectsFinal(session raw.SessionHandle) error {
	m.mu.Lock()
	pending, active := m.pending[session]
	delete(m.pending, session)
	m.mu.Unlock()
	if !active {
		return m.Module.FindObjectsFinal(session)
	}
	if pending.replay {
		return nil
	}
	if err := m.Module.FindObjectsFinal(session); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if pending.generation != m.generation || !pending.complete || pending.uncacheable {
		return nil
	}
	now := time.Now()
	// Reclaim expired entries when the cache fills. Otherwise leave eviction
	// off the request's hot path. A full cache simply skips this insertion.
	if len(m.entries) >= findCacheMaxEntries {
		for key, entry := range m.entries {
			if !now.Before(entry.expires) {
				delete(m.entries, key)
			}
		}
	}
	if len(m.entries) < findCacheMaxEntries {
		m.entries[pending.key] = findCacheEntry{
			handles: pending.recorded, generation: pending.generation,
			expires: now.Add(m.ttl),
		}
	}
	return nil
}

// FindAllObjects enumerates through the wrapped triple so replays and
// recording apply to one-shot searches too.
func (m *findCachingModule) FindAllObjects(session raw.SessionHandle, attributes []*raw.Attribute, batchSize int) (objects []raw.ObjectHandle, err error) {
	if batchSize <= 0 {
		batchSize = 64
	}
	if err = m.FindObjectsInit(session, attributes); err != nil {
		return nil, err
	}
	defer func() {
		if finalErr := m.FindObjectsFinal(session); err == nil && finalErr != nil {
			err = finalErr
		}
	}()
	for {
		batch, more, findErr := m.FindObjects(session, batchSize)
		objects = append(objects, batch...)
		if findErr != nil {
			return objects, findErr
		}
		if !more || len(batch) == 0 {
			return objects, nil
		}
	}
}

// SessionCancel only drops a search when its flag was requested and the
// cancellation succeeded. A cached search has no native find to cancel.
func (m *findCachingModule) SessionCancel(session raw.SessionHandle, flags uint) error {
	m.mu.Lock()
	pending := m.pending[session]
	m.mu.Unlock()
	nativeFlags := flags
	if pending != nil && pending.replay {
		nativeFlags &^= raw.CKF_FIND_OBJECTS
	}
	if nativeFlags != 0 || flags&raw.CKF_FIND_OBJECTS == 0 {
		if err := m.Module.SessionCancel(session, nativeFlags); err != nil {
			return err
		}
	}
	if flags&raw.CKF_FIND_OBJECTS != 0 {
		m.mu.Lock()
		if m.pending[session] == pending {
			delete(m.pending, session)
		}
		m.mu.Unlock()
	}
	return nil
}

func (m *findCachingModule) CloseSession(session raw.SessionHandle) error {
	err := m.Module.CloseSession(session)
	m.mu.Lock()
	delete(m.pending, session)
	for key := range m.entries {
		if key.session == session {
			delete(m.entries, key)
		}
	}
	m.mu.Unlock()
	return err
}

// Login, Logout, and session-object teardown change which objects a template
// matches, so each bumps the enumeration generation.
func (m *findCachingModule) Login(session raw.SessionHandle, userType uint, pin []byte) error {
	if err := m.Module.Login(session, userType, pin); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

func (m *findCachingModule) LoginUser(session raw.SessionHandle, userType uint, pin []byte, username string) error {
	if err := m.Module.LoginUser(session, userType, pin, username); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

func (m *findCachingModule) Logout(session raw.SessionHandle) error {
	if err := m.Module.Logout(session); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

func (m *findCachingModule) InitToken(slot raw.SlotID, pin []byte, label string) error {
	if err := m.Module.InitToken(slot, pin, label); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

// Object-mutating calls invalidate the enumeration cache on success.
func (m *findCachingModule) CreateObject(session raw.SessionHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.CreateObject(session, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) CopyObject(session raw.SessionHandle, object raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.CopyObject(session, object, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) DestroyObject(session raw.SessionHandle, object raw.ObjectHandle) error {
	if err := m.Module.DestroyObject(session, object); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

func (m *findCachingModule) SetAttributeValue(session raw.SessionHandle, object raw.ObjectHandle, attributes []*raw.Attribute) error {
	if err := m.Module.SetAttributeValue(session, object, attributes); err != nil {
		return err
	}
	m.invalidate()
	return nil
}

func (m *findCachingModule) GenerateKey(session raw.SessionHandle, mechanisms []*raw.Mechanism, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.GenerateKey(session, mechanisms, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) GenerateKeyPair(session raw.SessionHandle, mechanisms []*raw.Mechanism, publicAttributes, privateAttributes []*raw.Attribute) (raw.ObjectHandle, raw.ObjectHandle, error) {
	public, private, err := m.Module.GenerateKeyPair(session, mechanisms, publicAttributes, privateAttributes)
	if err == nil {
		m.invalidate()
	}
	return public, private, err
}

func (m *findCachingModule) UnwrapKey(session raw.SessionHandle, mechanisms []*raw.Mechanism, unwrappingKey raw.ObjectHandle, wrapped []byte, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.UnwrapKey(session, mechanisms, unwrappingKey, wrapped, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) UnwrapKeyAuthenticated(session raw.SessionHandle, mechanisms []*raw.Mechanism, unwrappingKey raw.ObjectHandle, wrapped []byte, attributes []*raw.Attribute, associatedData []byte) (raw.ObjectHandle, error) {
	handle, err := m.Module.UnwrapKeyAuthenticated(session, mechanisms, unwrappingKey, wrapped, attributes, associatedData)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) DeriveKey(session raw.SessionHandle, mechanisms []*raw.Mechanism, baseKey raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.DeriveKey(session, mechanisms, baseKey, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}

func (m *findCachingModule) EncapsulateKey(session raw.SessionHandle, mechanisms []*raw.Mechanism, publicKey raw.ObjectHandle, attributes []*raw.Attribute) ([]byte, raw.ObjectHandle, error) {
	ciphertext, handle, err := m.Module.EncapsulateKey(session, mechanisms, publicKey, attributes)
	if err == nil && handle != 0 {
		m.invalidate()
	}
	return ciphertext, handle, err
}

func (m *findCachingModule) DecapsulateKey(session raw.SessionHandle, mechanisms []*raw.Mechanism, decapsulationKey raw.ObjectHandle, ciphertext []byte, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	handle, err := m.Module.DecapsulateKey(session, mechanisms, decapsulationKey, ciphertext, attributes)
	if err == nil {
		m.invalidate()
	}
	return handle, err
}
