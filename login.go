package pkcs11

import (
	"context"

	"sync"

	"github.com/otpki/pkcs11/raw"
)

// loginKey identifies one logical PKCS #11 login state. Username participates
// because C_LoginUser can maintain distinct identities for the same user type.
type loginKey struct {
	slot     raw.SlotID
	userType uint
	username string
}

// loginEntry serializes the first login attempt for one key and records the
// module generation in which token-wide authentication was established.
type loginEntry struct {
	// mu ensures only one goroutine obtains a PIN and attempts login for this key.
	mu         sync.Mutex
	generation uint64
	loggedIn   bool
}

// loginCoordinator models the PKCS#11 application-wide login state while
// allowing internal adapters for modules that require per-session login calls.
type loginCoordinator struct {
	mu      sync.Mutex
	entries map[loginKey]*loginEntry
}

// newLoginCoordinator creates an empty application-login state table.
func newLoginCoordinator() *loginCoordinator {
	return &loginCoordinator{entries: make(map[loginKey]*loginEntry)}
}

// entry returns the stable per-key synchronization object, creating it while
// holding the coordinator map lock when necessary.
func (c *loginCoordinator) entry(key loginKey) *loginEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil {
		entry = &loginEntry{}
		c.entries[key] = entry
	}
	return entry
}

// ensure establishes the login scope selected by the adapter. Token-wide login
// is coalesced across sessions; session and context-specific login is always
// performed against the supplied handle.
func (c *loginCoordinator) ensure(ctx context.Context, pool *sessionPool, item pooledSession, purpose PINPurpose, userType uint) error {
	if pool == nil {
		return nil
	}
	scope := pool.currentDevice().plan.login.scope
	if purpose == PINPurposeContextSpecific || scope == loginScopeSession {
		return pool.loginDirect(ctx, item, purpose, userType)
	}
	// Auto uses standard token-wide application login semantics and falls back
	// through the normal CKR_USER_NOT_LOGGED_IN recovery path if a module does
	// not preserve that state across sessions.
	key := loginKey{slot: pool.currentDevice().Fingerprint.SlotID, userType: userType, username: pool.username}
	entry := c.entry(key)
	// Do not hold the global map mutex while obtaining credentials or entering
	// vendor code; unrelated slots and identities may authenticate concurrently.
	entry.mu.Lock()
	defer entry.mu.Unlock()
	generation := pool.module.currentGeneration()
	// Reinitialization invalidates any remembered application-login state even
	// when the token continues to expose the same slot and identity.
	if entry.loggedIn && entry.generation == generation {
		return nil
	}
	if err := pool.loginDirect(ctx, item, purpose, userType); err != nil {
		return err
	}
	entry.generation = generation
	entry.loggedIn = true
	return nil
}

// reset forgets all successful login observations after module-wide recovery or
// explicit client invalidation. It does not itself call C_Logout.
func (c *loginCoordinator) reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[loginKey]*loginEntry)
	c.mu.Unlock()
}

// resetSlot forgets observations for one slot after an explicit logout or token
// transition while retaining independent state for other slots.
func (c *loginCoordinator) resetSlot(slot raw.SlotID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for key := range c.entries {
		if key.slot == slot {
			delete(c.entries, key)
		}
	}
	c.mu.Unlock()
}
