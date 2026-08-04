package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// virtualSession is the connection-independent PKCS #11 session visible to one
// remote logical client. lease is nil for transaction-pooled sessions and is
// populated only while multipart operation state or session objects require
// affinity to one physical HSM session.
type virtualSession struct {
	// mu serializes operations made through this logical session and protects the
	// operation maps and last-used timestamp. Calls on different logical sessions
	// may proceed concurrently.
	mu sync.Mutex

	// lifetime protects the physical lease and closed state. Cross-session uses of
	// a session object hold a read lock for the complete native operation, while
	// close/discard/release paths take the write lock before ending the underlying
	// native session. This prevents a session object's owner from disappearing
	// while another logical session is using its native handle.
	lifetime sync.RWMutex

	handle    raw.SessionHandle
	slot      raw.SlotID
	flags     uint
	readWrite bool
	lastUsed  time.Time

	lease         *pkcs11.RawSessionLease
	pinnedCounted bool
	closed        bool

	operations map[string]bool
	parameters map[string][]*raw.Mechanism

	// Counts used by releaseIfIdle are atomic because an affine object may be
	// destroyed through a different logical session. Keeping these counts outside
	// mu avoids cross-session lock ordering and makes two sessions able to use or
	// destroy one another's session objects without deadlocking.
	operationCount atomic.Int64
	affineObjects  atomic.Int64
	activeCalls    atomic.Int64
}

func (session *virtualSession) touch() { session.lastUsed = time.Now() }

// hasPinnedLease reports whether this virtual session currently owns a physical
// session. Callers normally hold session.mu when using this diagnostic helper.
func (session *virtualSession) hasPinnedLease() bool {
	session.lifetime.RLock()
	ok := session.lease != nil && !session.closed
	session.lifetime.RUnlock()
	return ok
}

// pinnedLeaseIs reports whether lease is the currently pinned physical session.
func (session *virtualSession) pinnedLeaseIs(lease *pkcs11.RawSessionLease) bool {
	session.lifetime.RLock()
	ok := session.lease == lease && lease != nil && !session.closed
	session.lifetime.RUnlock()
	return ok
}

// beginPinnedUse borrows the current pinned lease for one native operation.
// activeCalls prevents a concurrent cross-session object deletion from releasing
// an otherwise idle lease between lookup and native execution.
func (session *virtualSession) beginPinnedUse(target *brokerTarget) (*pkcs11.RawSessionLease, func() error, bool) {
	session.lifetime.RLock()
	if session.closed || session.lease == nil {
		session.lifetime.RUnlock()
		return nil, nil, false
	}
	lease := session.lease
	session.activeCalls.Add(1)
	session.lifetime.RUnlock()

	finish := func() error {
		if remaining := session.activeCalls.Add(-1); remaining < 0 {
			panic("pkcs11 proxy: physical session active-call accounting underflow")
		}
		return session.releaseIfIdle(target)
	}
	return lease, finish, true
}

// ensureLease returns the pinned physical session when one exists, otherwise it
// checks out a temporary managed lease from the target's bounded pools. finish
// must be called when non-nil; it ends the active-use guard and may return the
// now-idle pinned lease to the physical pool.
func (session *virtualSession) ensureLease(ctx context.Context, target *brokerTarget, operation string) (*pkcs11.RawSessionLease, bool, func() error, error) {
	if lease, finish, ok := session.beginPinnedUse(target); ok {
		return lease, false, finish, nil
	}

	session.lifetime.RLock()
	closed := session.closed
	session.lifetime.RUnlock()
	if closed {
		return nil, false, nil, raw.Error(raw.CKR_SESSION_CLOSED)
	}

	lease, err := target.acquirePhysical(ctx, session.readWrite, operation)
	if err != nil {
		return nil, false, nil, err
	}
	return lease, true, nil, nil
}

// pin attaches lease to this virtual session. The caller must already have
// recorded a reason for affinity in operationCount or affineObjects; doing so
// before pinning prevents an unrelated cleanup path from seeing an idle lease.
func (session *virtualSession) pin(target *brokerTarget, lease *pkcs11.RawSessionLease) error {
	session.lifetime.Lock()
	defer session.lifetime.Unlock()
	if session.closed {
		return raw.Error(raw.CKR_SESSION_CLOSED)
	}
	if session.lease == lease {
		return nil
	}
	if session.lease != nil {
		return raw.Error(raw.CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}
	if err := target.reservePinned(); err != nil {
		return err
	}
	session.lease = lease
	session.pinnedCounted = true
	return nil
}

// releaseIfIdle returns the pinned physical session only when no operation,
// session object, or in-flight call still depends on it. It intentionally does
// not require session.mu so a cross-session object destruction can release the
// owner without acquiring another logical session's operation lock.
func (session *virtualSession) releaseIfIdle(target *brokerTarget) error {
	if session.operationCount.Load() != 0 || session.affineObjects.Load() != 0 || session.activeCalls.Load() != 0 {
		return nil
	}

	session.lifetime.Lock()
	defer session.lifetime.Unlock()
	if session.lease == nil || session.operationCount.Load() != 0 || session.affineObjects.Load() != 0 || session.activeCalls.Load() != 0 {
		return nil
	}
	lease := session.lease
	session.lease = nil
	if session.pinnedCounted {
		session.pinnedCounted = false
		target.releasePinned()
	}
	return lease.Close()
}

func (session *virtualSession) maybeRelease(target *brokerTarget) error {
	return session.releaseIfIdle(target)
}

func (session *virtualSession) hasOperation(name string) bool {
	if name == "" {
		return true
	}
	return session.operations[name] || session.operations["restored-operation"]
}

func (session *virtualSession) requireOperations(names []string) error {
	for _, name := range names {
		if !session.hasOperation(name) {
			return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
		}
	}
	return nil
}

func (session *virtualSession) clearOperationsLocked() {
	session.operations = make(map[string]bool)
	session.parameters = make(map[string][]*raw.Mechanism)
	session.operationCount.Store(0)
}

// cancelLeaseLocked discards a pinned physical session after an operation error
// or logical logout. The caller must hold session.mu. The lifetime write lock
// waits for cross-session users of affine objects before the native session is
// closed.
func (session *virtualSession) cancelLeaseLocked(target *brokerTarget) {
	session.clearOperationsLocked()
	session.affineObjects.Store(0)

	session.lifetime.Lock()
	defer session.lifetime.Unlock()
	if session.lease == nil {
		return
	}
	lease := session.lease
	session.lease = nil
	if session.pinnedCounted {
		session.pinnedCounted = false
		target.releasePinned()
	}
	lease.MarkBroken()
	_ = lease.Close()
}

func (session *virtualSession) cancelPinned(target *brokerTarget) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.cancelLeaseLocked(target)
}

func (session *virtualSession) close(target *brokerTarget) error {
	session.mu.Lock()
	defer session.mu.Unlock()

	session.lifetime.Lock()
	defer session.lifetime.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	dirty := session.operationCount.Load() != 0 || session.affineObjects.Load() != 0
	session.clearOperationsLocked()
	session.affineObjects.Store(0)
	if session.lease == nil {
		return nil
	}
	lease := session.lease
	session.lease = nil
	if session.pinnedCounted {
		session.pinnedCounted = false
		target.releasePinned()
	}
	// A session carrying an active operation or session object must be closed at
	// the native layer, not returned to the idle pool. MarkBroken gives the
	// managed pool that exact instruction while preserving normal cleanup.
	if dirty {
		lease.MarkBroken()
	}
	return lease.Close()
}

func (session *virtualSession) operationReady(descriptor operationDescriptor) bool {
	if len(descriptor.Required) == 0 {
		return true
	}
	if session.operations["restored-operation"] {
		return true
	}
	for _, name := range descriptor.Required {
		if !session.operations[name] {
			return false
		}
	}
	return true
}

func (session *virtualSession) startOperation(target *brokerTarget, name string, lease *pkcs11.RawSessionLease, mechanisms []*raw.Mechanism) error {
	if name == "" {
		return nil
	}
	if session.operations[name] {
		return raw.Error(raw.CKR_OPERATION_ACTIVE)
	}

	// Publish the operation count before pinning. A concurrent deletion of the
	// last affine object can then never mistake the new operation's lease for an
	// idle one and return it to the physical pool.
	session.operations[name] = true
	session.parameters[name] = mechanisms
	session.operationCount.Add(1)
	if err := session.pin(target, lease); err != nil {
		delete(session.operations, name)
		delete(session.parameters, name)
		if remaining := session.operationCount.Add(-1); remaining < 0 {
			panic("pkcs11 proxy: operation accounting underflow")
		}
		return err
	}
	return nil
}

func (session *virtualSession) deleteOperationLocked(name string) {
	if !session.operations[name] {
		delete(session.parameters, name)
		return
	}
	delete(session.operations, name)
	delete(session.parameters, name)
	if remaining := session.operationCount.Add(-1); remaining < 0 {
		panic("pkcs11 proxy: operation accounting underflow")
	}
}

func (session *virtualSession) cancelOperations(target *brokerTarget, names []string) ([]parameterUpdate, error) {
	var updates []parameterUpdate
	for _, name := range names {
		for _, mechanism := range session.parameters[name] {
			if mechanism == nil {
				continue
			}
			encoded, err := encodeParameter(mechanism.Parameter, target.registry)
			if err == nil {
				updates = append(updates, parameterUpdate{Session: uint64(session.handle), Operation: name, Parameter: encoded})
			}
		}
		session.deleteOperationLocked(name)
	}
	return updates, session.releaseIfIdle(target)
}

func (session *virtualSession) finishOperation(target *brokerTarget, name string) ([]parameterUpdate, error) {
	var updates []parameterUpdate
	for _, mechanism := range session.parameters[name] {
		if mechanism == nil {
			continue
		}
		encoded, err := encodeParameter(mechanism.Parameter, target.registry)
		if err == nil {
			updates = append(updates, parameterUpdate{Session: uint64(session.handle), Operation: name, Parameter: encoded})
		}
	}
	session.deleteOperationLocked(name)
	return updates, session.releaseIfIdle(target)
}
