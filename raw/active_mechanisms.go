package raw

import "sync"

// activeMechanismOperation identifies an operation whose marshaled
// CK_MECHANISM must outlive its *Init call. Some providers keep or update
// parameter pointers until the operation ends.
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

// activeMechanismStore owns marshaled mechanism data kept across multipart
// calls. It is separate from the module lifecycle lock. Retained mechanisms may
// also copy provider-updated fields, such as a generated GCM IV, back on free.
type activeMechanismStore struct {
	mu     sync.Mutex
	values map[activeMechanismKey]*nativeMechanism
}

// initializeMechanism runs one *Init call and, on success, transfers the
// mechanism to the active-operation store before releasing the module lease.
// On failure it frees the mechanism.
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

// retainMechanism stores one mechanism for an active session operation.
// Reinitializing the same operation replaces and frees the previous value.
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

// releaseMechanism frees the retained mechanism for one session operation.
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

// releaseSessionMechanismsByFlags frees only the operation classes selected
// by C_SessionCancel. Other active operation classes on the session remain.
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

// releaseSessionMechanisms frees all retained mechanism data for a session.
// Values are detached under the lock and freed afterward.
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

// releaseAllMechanisms frees all retained mechanism data before Ctx is
// destroyed. The map is detached under the lock and freed afterward.
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
