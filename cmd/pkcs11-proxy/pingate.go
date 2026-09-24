package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
)

const (
	defaultPINVerifierPoll    = 25 * time.Millisecond
	defaultPINVerifierTimeout = 30 * time.Second
)

// PINVerifier is a LogicalAuthenticator for PhysicalLoginClientActivated
// targets. It records the SHA-256 digest of the PIN that activated the current
// generation and requires every later logical login — including clients
// arriving after the target is already active — to present that same PIN. A
// parallel client therefore cannot piggyback on a peer's activation with an
// arbitrary or empty credential.
//
// The digest exists only in memory and is scoped to one activation generation;
// the verifier never retains, logs, or persists the PIN itself, matching the
// broker's own credential handling. When the coordinator invalidates physical
// login, the next activation starts a new generation and a fresh digest is
// recorded from that activation's leader.
//
// While no activation has completed, exactly one caller at a time is admitted
// as the activation candidate; its digest is kept keyed by principal. Other
// callers wait for the attempt to resolve and are then verified against the
// digest of the principal the coordinator reports as the activator
// (ActivationStatus.ActivatedBy), which is the only authoritative record of
// which PIN the HSM accepted.
type PINVerifier struct {
	mu sync.Mutex

	status func() proxy.ActivationStatus

	generation uint64
	digest     [32]byte
	armed      bool
	pending    string
	candidates map[string][32]byte

	// WaitPollInterval is how often a gated caller re-reads activation state.
	// WaitTimeout bounds the time a caller waits for an in-flight activation
	// before it is allowed to contend for leadership itself, recovering from a
	// candidate that never reached the broker.
	WaitPollInterval time.Duration
	WaitTimeout      time.Duration
}

// NewPINVerifier creates an unbound verifier. Call Observe before serving.
func NewPINVerifier() *PINVerifier {
	return &PINVerifier{candidates: make(map[string][32]byte)}
}

// Observe wires the activation snapshot source, normally a closure over
// Server.TargetStats for the guarded route. It must be called before the
// verifier authenticates traffic; until then the verifier behaves as if the
// target is permanently inactive and admits one candidate at a time.
func (v *PINVerifier) Observe(status func() proxy.ActivationStatus) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.status = status
}

func (v *PINVerifier) snapshot() proxy.ActivationStatus {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.status == nil {
		return proxy.ActivationStatus{State: proxy.ActivationInactive}
	}
	return v.status()
}

func (v *PINVerifier) normalized() (poll, timeout time.Duration) {
	poll, timeout = v.WaitPollInterval, v.WaitTimeout
	if poll <= 0 {
		poll = defaultPINVerifierPoll
	}
	if timeout <= 0 {
		timeout = defaultPINVerifierTimeout
	}
	return poll, timeout
}

// Authenticate implements proxy.LogicalAuthenticator. The supplied PIN is
// hashed immediately and never retained.
func (v *PINVerifier) Authenticate(ctx context.Context, attempt proxy.LoginAttempt) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sum := sha256.Sum256(attempt.PIN)
	for {
		status := v.snapshot()
		v.mu.Lock()
		switch status.State {
		case proxy.ActivationActive:
			if v.generation != status.Generation {
				// A new activation epoch: promote the candidate recorded for the
				// caller the coordinator reports as the activator.
				candidate, ok := v.candidates[status.ActivatedBy]
				clear(v.candidates)
				v.pending = ""
				v.generation = status.Generation
				v.digest = candidate
				v.armed = ok
			}
			ok := v.armed && subtle.ConstantTimeCompare(v.digest[:], sum[:]) == 1
			v.mu.Unlock()
			if !ok {
				return raw.Error(raw.CKR_PIN_INCORRECT)
			}
			return nil
		default:
			if status.State == proxy.ActivationInactive {
				if v.pending == "" || v.pending == attempt.Identity.Principal {
					// Admit one activation candidate. Its physical C_Login is the
					// only arbiter of PIN correctness while the token is cold.
					v.pending = attempt.Identity.Principal
					v.candidates[v.pending] = sum
					v.mu.Unlock()
					return nil
				}
			}
			v.mu.Unlock()
			if err := v.waitResolved(ctx, status); err != nil {
				return err
			}
		}
	}
}

// waitResolved blocks until the activation coordinator reports a state or
// generation change, or until the bounded wait expires. Expiry clears the
// pending candidate so a caller that never reached the broker cannot block
// activation forever.
func (v *PINVerifier) waitResolved(ctx context.Context, from proxy.ActivationStatus) error {
	poll, timeout := v.normalized()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		current := v.snapshot()
		if current.State != from.State || current.Generation != from.Generation {
			return nil
		}
		if time.Now().After(deadline) {
			v.mu.Lock()
			v.pending = ""
			v.mu.Unlock()
			return nil
		}
	}
}
