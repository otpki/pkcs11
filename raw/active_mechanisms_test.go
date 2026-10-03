package raw

import "testing"

func retainedTestMechanism(t *testing.T) *nativeMechanism {
	t.Helper()
	arena := &nativeArena{}
	_, root, err := arena.alloc(1)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeMechanism{abi: HostNativeABI(), arena: arena, root: root}
}

// This test verifies that releaseSessionMechanismsByFlags releases only the active operations selected by the
// supplied PKCS #11 flags, and only for the specified session.
func TestReleaseSessionMechanismsByFlagsPreservesUnselectedOperations(t *testing.T) {
	ctx := &Ctx{}
	session := SessionHandle(7)
	other := SessionHandle(8)

	for _, operation := range []activeMechanismOperation{
		activeEncrypt,
		activeDecrypt,
		activeSign,
		activeVerify,
		activeVerifySignature,
		activeMessageSign,
	} {
		ctx.retainMechanism(session, operation, retainedTestMechanism(t))
	}
	ctx.retainMechanism(other, activeSign, retainedTestMechanism(t))
	defer ctx.releaseAllMechanisms()

	ctx.releaseSessionMechanismsByFlags(session, CKF_SIGN|CKF_VERIFY)

	ctx.active.mu.Lock()
	defer ctx.active.mu.Unlock()
	for _, operation := range []activeMechanismOperation{activeSign, activeVerify, activeVerifySignature} {
		if _, ok := ctx.active.values[activeMechanismKey{session: session, operation: operation}]; ok {
			t.Errorf("operation %d was not released", operation)
		}
	}
	for _, operation := range []activeMechanismOperation{activeEncrypt, activeDecrypt, activeMessageSign} {
		if _, ok := ctx.active.values[activeMechanismKey{session: session, operation: operation}]; !ok {
			t.Errorf("operation %d was released even though its flag was not selected", operation)
		}
	}
	if _, ok := ctx.active.values[activeMechanismKey{session: other, operation: activeSign}]; !ok {
		t.Error("operation on another session was released")
	}
}
