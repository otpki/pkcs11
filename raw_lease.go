package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/otpki/pkcs11/raw"
)

// RawSessionLease is long-lived exclusive ownership of one managed PKCS #11
// session. It is intended for infrastructure such as the network proxy that
// must preserve multipart operation or session-object affinity across several
// calls.
//
// A lease keeps the module loaded, preserves any required OS-thread affinity,
// participates in the client's total session budget, and returns the native
// handle to the pool only when Close is called. Calls must be serialized by the
// owner; concurrent Call invocations on one lease are rejected.
type RawSessionLease struct {
	lease     *sessionLease
	mu        sync.Mutex
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// AcquireRawSession obtains an exclusive managed session without wrapping it in
// an automatic retry loop. Infrastructure retaining a lease across calls must
// decide explicitly whether an interrupted stateful operation can be retried.
func (c *Client) AcquireRawSession(ctx context.Context, options RawSessionOptions) (*RawSessionLease, error) {
	if c == nil || c.closed.Load() {
		return nil, errors.New("pkcs11: client is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pool := c.roPool
	if options.ReadWrite {
		pool = c.rwPool
	}
	lease, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	operation := strings.TrimSpace(options.Operation)
	if operation == "" {
		operation = "raw-session-lease"
	}
	lease.operation = operation
	lease.attempt = 1
	return &RawSessionLease{lease: lease}, nil
}

// Call executes one raw operation on the retained session while preserving
// module serialization, thread affinity, hooks, and broken-session detection.
func (lease *RawSessionLease) Call(ctx context.Context, operation string, fn func(raw.Module, raw.SessionHandle) error) error {
	if lease == nil || lease.lease == nil || lease.closed.Load() {
		return errors.New("pkcs11: raw session lease is closed")
	}
	if fn == nil {
		return fmt.Errorf("pkcs11: nil raw session lease callback")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed.Load() {
		return errors.New("pkcs11: raw session lease is closed")
	}
	if operation == "" {
		operation = lease.lease.operation
	}
	return lease.lease.callContext(ctx, operation, func(module raw.Module) error {
		return fn(module, lease.lease.handle)
	})
}

// EnsureAuthentication establishes session-scoped authentication once for this
// exact healthy native session. identity must change whenever the physical
// credential, user type, username, target generation, or authorization domain
// changes. The callback runs under the lease's serialization lock.
func (lease *RawSessionLease) EnsureAuthentication(ctx context.Context, identity string, fn func(raw.Module, raw.SessionHandle) error) error {
	if lease == nil || lease.lease == nil || lease.closed.Load() {
		return errors.New("pkcs11: raw session lease is closed")
	}
	if identity == "" {
		return fmt.Errorf("pkcs11: authentication identity is required")
	}
	if fn == nil {
		return fmt.Errorf("pkcs11: nil authentication callback")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed.Load() {
		return errors.New("pkcs11: raw session lease is closed")
	}
	if lease.lease.authentication == identity {
		return nil
	}
	if ctx == nil {
		ctx = lease.lease.Context()
	}
	err := lease.lease.callContext(ctx, "raw-session-authenticate", func(module raw.Module) error {
		return fn(module, lease.lease.handle)
	})
	if err != nil {
		return err
	}
	lease.lease.authentication = identity
	return nil
}

// InvalidateAuthentication forgets session-scoped authentication after the
// provider reports CKR_USER_NOT_LOGGED_IN or the broker changes identity. It
// does not call C_Logout.
func (lease *RawSessionLease) InvalidateAuthentication() {
	if lease == nil || lease.lease == nil {
		return
	}
	lease.mu.Lock()
	lease.lease.authentication = ""
	lease.mu.Unlock()
}

// ContextLogin performs a context-specific login on this exact retained
// physical session, as required by CKA_ALWAYS_AUTHENTICATE keys.
func (lease *RawSessionLease) ContextLogin(ctx context.Context) error {
	if lease == nil || lease.lease == nil || lease.closed.Load() {
		return errors.New("pkcs11: raw session lease is closed")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if ctx == nil {
		ctx = lease.lease.Context()
	}
	return lease.lease.pool.ContextLogin(ctx, lease.lease.handle, lease.lease.worker)
}

// Handle returns the native handle for diagnostics. It is valid only while the
// lease remains open and must never be sent to another process.
func (lease *RawSessionLease) Handle() raw.SessionHandle {
	if lease == nil || lease.lease == nil || lease.closed.Load() {
		return 0
	}
	return lease.lease.handle
}

// ReadWrite reports whether the retained physical session is read/write.
func (lease *RawSessionLease) ReadWrite() bool {
	return lease != nil && lease.lease != nil && lease.lease.ReadWrite()
}

// MarkBroken prevents the physical session from returning to the idle pool.
func (lease *RawSessionLease) MarkBroken() {
	if lease != nil && lease.lease != nil {
		lease.lease.MarkBroken()
	}
}

// Close releases the retained session. It is safe to call repeatedly.
func (lease *RawSessionLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.closeOnce.Do(func() {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		lease.closed.Store(true)
		if lease.lease != nil {
			lease.closeErr = lease.lease.Close()
		}
	})
	return lease.closeErr
}
