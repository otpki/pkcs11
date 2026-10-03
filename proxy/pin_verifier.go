package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
)

// pinVerifier checks later client PINs against the PIN accepted during physical
// activation. It stores an HMAC-SHA-256 under a random per-target key, never the
// PIN itself. Comparisons are constant-time and do not spend an HSM retry.
// This verifier has no attempt limit. HSM lockout and activation cooldown do
// not protect this software path from PIN guessing.
//
// The verifier is bound to one activation generation and is cleared when that
// activation is lost. Target close wipes both the digest and HMAC key.
type pinVerifier struct {
	mu         sync.Mutex
	key        [32]byte
	digest     []byte
	generation uint64
	armed      bool
}

func newPINVerifier() (*pinVerifier, error) {
	verifier := &pinVerifier{}
	if _, err := rand.Read(verifier.key[:]); err != nil {
		return nil, err
	}
	return verifier, nil
}

// arm records the digest of pin bound to one activation generation, replacing
// any previously armed value. pin is read once and never retained.
func (v *pinVerifier) arm(pin []byte, generation uint64) {
	if v == nil {
		return
	}
	mac := hmac.New(sha256.New, v.key[:])
	_, _ = mac.Write(pin)
	digest := mac.Sum(nil)
	v.mu.Lock()
	wipe(v.digest)
	v.digest = digest
	v.generation = generation
	v.armed = true
	v.mu.Unlock()
}

// verify reports whether a verifier is armed for generation and whether pin
// matches it. A disarmed verifier falls through to physical activation.
func (v *pinVerifier) verify(pin []byte, generation uint64) (armed, matched bool) {
	if v == nil {
		return false, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.armed || v.generation != generation {
		return false, false
	}
	mac := hmac.New(sha256.New, v.key[:])
	_, _ = mac.Write(pin)
	return true, hmac.Equal(mac.Sum(nil), v.digest)
}

// clear drops the armed digest when physical login is invalidated. The key
// survives so the next activation re-arms under it.
func (v *pinVerifier) clear() {
	if v == nil {
		return
	}
	v.mu.Lock()
	wipe(v.digest)
	v.digest = nil
	v.generation = 0
	v.armed = false
	v.mu.Unlock()
}

// destroy wipes the key and digest on broker target close.
func (v *pinVerifier) destroy() {
	if v == nil {
		return
	}
	v.mu.Lock()
	wipe(v.key[:])
	wipe(v.digest)
	v.digest = nil
	v.armed = false
	v.mu.Unlock()
}
