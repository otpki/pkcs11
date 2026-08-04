package raw

import "sync"

// activeMechanismOperation identifies a PKCS #11 operation whose marshaled
// CK_MECHANISM must remain alive after the corresponding *Init call returns.
//
// Initialization calls are permitted to establish operation state that outlives
// the call itself. Some modules retain or later write through pointers reachable
// from CK_MECHANISM.pParameter. The driver therefore keeps the complete
// nativeMechanism allocation alive until the operation is completed, canceled, replaced,
// or its session is closed.
type activeMechanismOperation uint8

const (
	// Each value identifies the Cryptoki operation state established by the
	// corresponding initialization function. Keeping them distinct permits the
	// operation classes that Cryptoki allows concurrently on one session.
	activeEncrypt activeMechanismOperation = iota + 1
	activeDecrypt
	activeDigest
	activeSign
	activeSignRecover
	activeVerify
	activeVerifyRecover
	activeMessageEncrypt
	activeMessageDecrypt
	activeMessageSign
	activeMessageVerify
	activeVerifySignature
)

// activeMechanismKey distinguishes independently active operation classes on a
// session. PKCS #11 permits a session to hold different kinds of operation state
// concurrently, so a session handle alone is not a sufficient map key.
type activeMechanismKey struct {
	session   SessionHandle
	operation activeMechanismOperation
}

// activeMechanismStore owns marshaled mechanisms whose native allocations must
// outlive an initialization call.
//
// The store is part of Ctx and is protected independently of the context's
// module-lifecycle mutex. Its values are owned exclusively by the store: after a
// mechanism is retained, exactly one replacement or release path must call
// nativeMechanism.free.
//
// A retained mechanism can also contain a syncBack callback. For example, some
// GCM implementations write a generated IV into the native parameter structure.
// Keeping the nativeMechanism until the operation ends allows free to copy those
// final values back into the caller-owned Go parameter before releasing native memory.
type activeMechanismStore struct {
	mu     sync.Mutex
	values map[activeMechanismKey]*nativeMechanism
}

// initializeMechanism enters a provider initialization function and commits
// ownership of mechanism to the active-operation store before releasing the
// context's native-library lease. Keeping the commit inside the lifecycle read
// lock prevents Destroy from unloading the module and clearing the store in the
// small interval between a successful C_*Init call and mechanism retention.
//
// invoke must make exactly one native call through c.call and must not release
// mechanism. On failure this helper frees it; on success the store owns it.
func (c *Ctx) initializeMechanism(
	session SessionHandle,
	operation activeMechanismOperation,
	mechanism *nativeMechanism,
	invoke func() uint,
) error {
	if mechanism == nil {
		panic("pkcs11: internal nil mechanism initialization")
	}
	if invoke == nil {
		mechanism.free()
		panic("pkcs11: internal nil mechanism initializer")
	}
	_, unlock, err := c.locked()
	if err != nil {
		mechanism.free()
		return err
	}

	callErr := rv(invoke())
	if callErr == nil {
		c.retainMechanism(session, operation, mechanism)
	}
	unlock()

	if callErr != nil {
		mechanism.free()
	}
	return callErr
}

// retainMechanism transfers ownership of mechanism to the context and associates
// it with one active operation on one session.
//
// A successful second *Init call for the same session and operation replaces the
// previous operation state. The old mechanism is removed while holding the map
// lock, then freed after unlocking. Keeping free outside the critical section
// avoids holding the store lock during native cleanup or parameter sync-back.
//
// A nil context or mechanism has nothing to retain and is intentionally ignored.
func (c *Ctx) retainMechanism(session SessionHandle, operation activeMechanismOperation, mechanism *nativeMechanism) {
	if c == nil || mechanism == nil {
		return
	}

	key := activeMechanismKey{session: session, operation: operation}

	c.active.mu.Lock()
	if c.active.values == nil {
		c.active.values = make(map[activeMechanismKey]*nativeMechanism)
	}
	old := c.active.values[key]
	c.active.values[key] = mechanism
	c.active.mu.Unlock()

	if old != nil {
		old.free()
	}
}

// releaseMechanism completes ownership cleanup for one operation on one session.
// It is called after a single-part operation, after the corresponding *Final
// call, or from another path that knows this operation is no longer active.
//
// Deleting from a nil map is safe, so this method also handles sessions that have
// no retained mechanism. As in retainMechanism, freeing occurs after unlocking
// to keep the critical section limited to map access.
func (c *Ctx) releaseMechanism(session SessionHandle, operation activeMechanismOperation) {
	if c == nil {
		return
	}

	key := activeMechanismKey{session: session, operation: operation}

	c.active.mu.Lock()
	mechanism := c.active.values[key]
	delete(c.active.values, key)
	c.active.mu.Unlock()

	if mechanism != nil {
		mechanism.free()
	}
}

// releaseSessionMechanismsByFlags releases only the operation classes selected
// by C_SessionCancel flags. Cryptoki permits independent operation classes on a
// session, so canceling signing must not release an unrelated active encryption
// parameter graph.
func (c *Ctx) releaseSessionMechanismsByFlags(session SessionHandle, flags uint) {
	if c == nil || flags == 0 {
		return
	}

	operations := make([]activeMechanismOperation, 0, 12)
	appendOperation := func(flag uint, values ...activeMechanismOperation) {
		if flags&flag != 0 {
			operations = append(operations, values...)
		}
	}
	appendOperation(CKF_ENCRYPT, activeEncrypt)
	appendOperation(CKF_DECRYPT, activeDecrypt)
	appendOperation(CKF_DIGEST, activeDigest)
	appendOperation(CKF_SIGN, activeSign)
	appendOperation(CKF_SIGN_RECOVER, activeSignRecover)
	appendOperation(CKF_VERIFY, activeVerify, activeVerifySignature)
	appendOperation(CKF_VERIFY_RECOVER, activeVerifyRecover)
	appendOperation(CKF_MESSAGE_ENCRYPT, activeMessageEncrypt)
	appendOperation(CKF_MESSAGE_DECRYPT, activeMessageDecrypt)
	appendOperation(CKF_MESSAGE_SIGN, activeMessageSign)
	appendOperation(CKF_MESSAGE_VERIFY, activeMessageVerify)

	var release []*nativeMechanism
	c.active.mu.Lock()
	for _, operation := range operations {
		key := activeMechanismKey{session: session, operation: operation}
		if mechanism := c.active.values[key]; mechanism != nil {
			release = append(release, mechanism)
			delete(c.active.values, key)
		}
	}
	c.active.mu.Unlock()

	for _, mechanism := range release {
		mechanism.free()
	}
}

// releaseSessionMechanisms releases every retained mechanism associated with a
// session. Session teardown and cancellation use this as a safety net because
// an operation may end without reaching its normal Encrypt, Decrypt, or *Final
// cleanup path.
//
// Matching values are first detached from the shared map under the lock. They
// are then freed after unlocking so no potentially expensive native cleanup or
// sync-back work blocks unrelated sessions from updating the store.
func (c *Ctx) releaseSessionMechanisms(session SessionHandle) {
	if c == nil {
		return
	}

	var release []*nativeMechanism

	c.active.mu.Lock()
	for key, mechanism := range c.active.values {
		if key.session == session {
			release = append(release, mechanism)
			delete(c.active.values, key)
		}
	}
	c.active.mu.Unlock()

	for _, mechanism := range release {
		mechanism.free()
	}
}

// releaseAllMechanisms detaches and frees every retained mechanism owned by the
// context. Ctx.Destroy uses this before unloading the PKCS #11 module so no
// native parameter allocation or pending sync-back callback survives context
// shutdown.
//
// Replacing the map with nil makes the detach operation constant-time while the
// lock is held. A later retainMechanism call can lazily allocate a new map,
// although normal lifecycle coordination prevents new operations after Destroy.
func (c *Ctx) releaseAllMechanisms() {
	if c == nil {
		return
	}

	c.active.mu.Lock()
	values := c.active.values
	c.active.values = nil
	c.active.mu.Unlock()

	for _, mechanism := range values {
		mechanism.free()
	}
}
