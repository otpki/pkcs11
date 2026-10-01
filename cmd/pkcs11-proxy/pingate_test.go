package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
)

type fakeActivation struct {
	mu     sync.Mutex
	status proxy.ActivationStatus
}

func (f *fakeActivation) set(state proxy.ActivationState, generation uint64, activatedBy string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = proxy.ActivationStatus{State: state, Generation: generation, ActivatedAt: time.Now(), ActivatedBy: activatedBy}
}

func (f *fakeActivation) snapshot() proxy.ActivationStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func newTestVerifier(source *fakeActivation) *PINVerifier {
	verifier := NewPINVerifier()
	verifier.WaitPollInterval = time.Millisecond
	verifier.WaitTimeout = 50 * time.Millisecond
	verifier.Observe(source.snapshot)
	return verifier
}

func attempt(principal string, pin string) proxy.LoginAttempt {
	return proxy.LoginAttempt{
		Identity: proxy.RequestIdentity{Principal: principal},
		UserType: raw.CKU_USER,
		PIN:      []byte(pin),
	}
}

func TestPINVerifierAdmitsSingleActivationCandidate(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationInactive, 0, "")
	verifier := newTestVerifier(source)

	if err := verifier.Authenticate(context.Background(), attempt("leader", "pin-1")); err != nil {
		t.Fatalf("leader authenticate: %v", err)
	}
	// The same principal may retry while still pending.
	if err := verifier.Authenticate(context.Background(), attempt("leader", "pin-1")); err != nil {
		t.Fatalf("leader retry authenticate: %v", err)
	}
	verifier.mu.Lock()
	if verifier.pending != "leader" || len(verifier.candidates) != 1 {
		verifier.mu.Unlock()
		t.Fatalf("candidate state = %#v", verifier.candidates)
	}
	want := sha256.Sum256([]byte("pin-1"))
	if verifier.candidates["leader"] != want {
		verifier.mu.Unlock()
		t.Fatal("candidate digest mismatch")
	}
	verifier.mu.Unlock()
}

func TestPINVerifierFollowerWaitsForActivation(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationInactive, 0, "")
	verifier := newTestVerifier(source)

	if err := verifier.Authenticate(context.Background(), attempt("leader", "correct")); err != nil {
		t.Fatalf("leader authenticate: %v", err)
	}
	source.set(proxy.ActivationActivating, 0, "")

	done := make(chan error, 1)
	go func() { done <- verifier.Authenticate(context.Background(), attempt("follower", "correct")) }()

	// While the attempt is in flight the follower must not be admitted.
	select {
	case err := <-done:
		t.Fatalf("follower returned early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	source.set(proxy.ActivationActive, 1, "leader")
	if err := <-done; err != nil {
		t.Fatalf("follower authenticate after activation: %v", err)
	}
}

func TestPINVerifierRejectsPiggybackAfterActivation(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationInactive, 0, "")
	verifier := newTestVerifier(source)

	if err := verifier.Authenticate(context.Background(), attempt("leader", "correct")); err != nil {
		t.Fatalf("leader authenticate: %v", err)
	}
	source.set(proxy.ActivationActive, 1, "leader")

	if err := verifier.Authenticate(context.Background(), attempt("follower", "wrong-pin")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("wrong PIN after activation = %v, want CKR_PIN_INCORRECT", err)
	}
	if err := verifier.Authenticate(context.Background(), attempt("follower", "correct")); err != nil {
		t.Fatalf("correct PIN after activation = %v", err)
	}
}

func TestPINVerifierReArmsOnNewGeneration(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationInactive, 0, "")
	verifier := newTestVerifier(source)

	if err := verifier.Authenticate(context.Background(), attempt("leader", "first")); err != nil {
		t.Fatalf("leader authenticate: %v", err)
	}
	source.set(proxy.ActivationActive, 1, "leader")
	if err := verifier.Authenticate(context.Background(), attempt("other", "first")); err != nil {
		t.Fatalf("verify first generation: %v", err)
	}

	// Physical login is lost and a different principal re-activates with a
	// different PIN: the verifier must re-arm from the new activator.
	source.set(proxy.ActivationInactive, 1, "")
	if err := verifier.Authenticate(context.Background(), attempt("second", "second-pin")); err != nil {
		t.Fatalf("second leader authenticate: %v", err)
	}
	source.set(proxy.ActivationActive, 2, "second")
	if err := verifier.Authenticate(context.Background(), attempt("other", "first")); !raw.IsError(err, raw.CKR_PIN_INCORRECT) {
		t.Fatalf("stale-generation PIN = %v, want CKR_PIN_INCORRECT", err)
	}
	if err := verifier.Authenticate(context.Background(), attempt("other", "second-pin")); err != nil {
		t.Fatalf("verify second generation: %v", err)
	}
}

func TestPINVerifierRecoversDeadCandidate(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationInactive, 0, "")
	verifier := newTestVerifier(source)

	if err := verifier.Authenticate(context.Background(), attempt("stalled", "pin")); err != nil {
		t.Fatalf("candidate authenticate: %v", err)
	}
	// The candidate never reaches the broker. After the bounded wait another
	// principal must be allowed to contend for leadership.
	if err := verifier.Authenticate(context.Background(), attempt("next", "pin")); err != nil {
		t.Fatalf("recovery authenticate: %v", err)
	}
	verifier.mu.Lock()
	if verifier.pending != "next" {
		verifier.mu.Unlock()
		t.Fatal("pending candidate was not recovered")
	}
	verifier.mu.Unlock()
}

func TestPINVerifierWaitHonorsContextCancel(t *testing.T) {
	source := &fakeActivation{}
	source.set(proxy.ActivationActivating, 0, "")
	verifier := newTestVerifier(source)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- verifier.Authenticate(ctx, attempt("follower", "pin")) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait = %v, want context.Canceled", err)
	}
}
