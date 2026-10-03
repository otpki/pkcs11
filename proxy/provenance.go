package proxy

import (
	"sync"

	"github.com/otpki/pkcs11/raw"
)

// errForeignSessionObject reports an attempt to use a session object owned by
// another logical client. It carries the standard CKR_OBJECT_HANDLE_INVALID
// result so callers observe the ordinary invalid-handle error; the find path
// matches it with errors.Is to silently filter foreign search results.
var errForeignSessionObject = raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)

// objectScopeKey groups routes that share one native Cryptoki application and token slot.
// Session-object ownership must be enforced across the whole scope.
type objectScopeKey struct {
	module string
	slot   raw.SlotID
}

// objectProvenance records the logical client and virtual session that created a native session object.
type objectProvenance struct {
	clientID     [16]byte
	ownerSession raw.SessionHandle
	uniqueID     string
}

// sessionObjectRegistry tracks session-object ownership for one native module and token scope.
type sessionObjectRegistry struct {
	scope objectScopeKey

	mu      sync.Mutex
	objects map[raw.ObjectHandle]objectProvenance
	refs    int
}

// provenanceScopes indexes the live registries by native scope. Entries are
// removed when the last referencing target closes so a restarted or
// re-initialized module can never inherit stale handle records.
var provenanceScopes = struct {
	sync.Mutex
	scopes map[objectScopeKey]*sessionObjectRegistry
}{scopes: make(map[objectScopeKey]*sessionObjectRegistry)}

// acquireObjectScope returns the shared registry for (module, slot), creating
// it when this is the first target bound to that scope.
func acquireObjectScope(moduleKey string, slot raw.SlotID) *sessionObjectRegistry {
	provenanceScopes.Lock()
	defer provenanceScopes.Unlock()
	key := objectScopeKey{module: moduleKey, slot: slot}
	scope := provenanceScopes.scopes[key]
	if scope == nil {
		scope = &sessionObjectRegistry{scope: key, objects: make(map[raw.ObjectHandle]objectProvenance)}
		provenanceScopes.scopes[key] = scope
	}
	scope.refs++
	return scope
}

// release drops this target's reference. When the last reference is released
// the whole scope is discarded — a module reload or process restart produces a
// fresh scope so stale native handles cannot match new objects.
func (registry *sessionObjectRegistry) release() {
	provenanceScopes.Lock()
	defer provenanceScopes.Unlock()
	registry.refs--
	if registry.refs > 0 {
		return
	}
	registry.mu.Lock()
	registry.objects = nil
	registry.mu.Unlock()
	delete(provenanceScopes.scopes, registry.scope)
}

// register records that clientID created the session object native on
// ownerSession. The caller publishes the virtual handle only after this
// succeeds; a later failure must drop the record again.
func (registry *sessionObjectRegistry) register(native raw.ObjectHandle, clientID [16]byte, ownerSession raw.SessionHandle, uniqueID string) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.objects[native] = objectProvenance{clientID: clientID, ownerSession: ownerSession, uniqueID: uniqueID}
}

// admit reports whether clientID may wrap the discovered session object
// identified by native and currently carrying uniqueID. A record whose stored
// unique ID no longer matches the object occupying the handle is stale (the
// native module reused the handle) and is dropped instead of admitting.
func (registry *sessionObjectRegistry) admit(native raw.ObjectHandle, clientID [16]byte, uniqueID string) (objectProvenance, bool) {
	if registry == nil {
		return objectProvenance{}, false
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	provenance, ok := registry.objects[native]
	if !ok || provenance.clientID != clientID {
		return objectProvenance{}, false
	}
	if provenance.uniqueID != "" && uniqueID != "" && provenance.uniqueID != uniqueID {
		delete(registry.objects, native)
		return objectProvenance{}, false
	}
	return provenance, true
}

func (registry *sessionObjectRegistry) drop(native raw.ObjectHandle) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	delete(registry.objects, native)
	registry.mu.Unlock()
}

// dropOwned removes every record created by clientID on ownerSession.
func (registry *sessionObjectRegistry) dropOwned(clientID [16]byte, ownerSession raw.SessionHandle) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	for handle, provenance := range registry.objects {
		if provenance.clientID == clientID && provenance.ownerSession == ownerSession {
			delete(registry.objects, handle)
		}
	}
	registry.mu.Unlock()
}

// dropClient removes every record created by clientID.
func (registry *sessionObjectRegistry) dropClient(clientID [16]byte) {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	for handle, provenance := range registry.objects {
		if provenance.clientID == clientID {
			delete(registry.objects, handle)
		}
	}
	registry.mu.Unlock()
}

// dropAll removes every record; used when the token itself was wiped
// (C_InitToken) or the underlying native application instance was replaced.
func (registry *sessionObjectRegistry) dropAll() {
	if registry == nil {
		return
	}
	registry.mu.Lock()
	registry.objects = make(map[raw.ObjectHandle]objectProvenance)
	registry.mu.Unlock()
}
