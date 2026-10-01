package raw

import "fmt"

type outputCall func(output, lengthPointer uintptr) uint

// callOutput implements the PKCS #11 variable-length output convention while
// keeping every output and length buffer alive for the duration of each native
// call. The bounded fallback supports modules that reject a nil sizing probe.
func (c *Ctx) callOutput(call outputCall) ([]byte, error) {
	policy := c.outputBufferPolicy()
	abi := c.abi
	requested := policy.InitialSize

	if !policy.RejectNullProbe {
		arena := &nativeArena{}
		lengthPointer, lengthBytes, err := arena.alloc(abi.ULongSize)
		if err != nil {
			return nil, err
		}
		value := call(0, lengthPointer)
		requested = abi.getULong(lengthBytes, 0)
		arena.close()
		if value != CKR_OK && value != CKR_BUFFER_TOO_SMALL {
			return nil, rv(value)
		}
	}

	for range 16 {
		if requested > policy.MaximumSize {
			return nil, fmt.Errorf("pkcs11: output buffer request %d exceeds configured maximum %d", requested, policy.MaximumSize)
		}
		arena := &nativeArena{}
		lengthPointer, lengthBytes, err := arena.alloc(abi.ULongSize)
		if err != nil {
			return nil, err
		}
		abi.putULong(lengthBytes, 0, requested)
		outputPointer, output, err := nativeAlloc(arena, requested)
		if err != nil {
			arena.close()
			return nil, err
		}
		value := call(outputPointer, lengthPointer)
		returned := abi.getULong(lengthBytes, 0)
		if value == CKR_BUFFER_TOO_SMALL {
			arena.close()
			switch {
			case returned > requested:
				requested = returned
			case requested == 0:
				requested = policy.InitialSize
			case requested > policy.MaximumSize/2:
				requested = policy.MaximumSize + 1
			default:
				requested *= 2
			}
			continue
		}
		if err := rv(value); err != nil {
			arena.close()
			return nil, err
		}
		if returned > requested {
			arena.close()
			return nil, fmt.Errorf("pkcs11: module returned output length %d for a %d-byte buffer", returned, requested)
		}
		size, err := abi.checkedLength(returned)
		if err != nil {
			arena.close()
			return nil, err
		}
		result := append([]byte(nil), output[:size]...)
		arena.close()
		return result, nil
	}
	return nil, Error(CKR_BUFFER_TOO_SMALL)
}

func (c *Ctx) EncryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return err
	}
	return c.initializeMechanism(session, activeEncrypt, mechanism, func() uint {
		return c.call(functionEncryptInit,
			c.abi.ulongArgument(uint(session)), mechanism.pointer(), c.abi.ulongArgument(uint(key)))
	})
}

func (c *Ctx) Encrypt(session SessionHandle, plaintext []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeEncrypt)
	arena := &nativeArena{}
	defer arena.close()
	input, err := nativeCopy(arena, plaintext)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionEncrypt, c.abi.ulongArgument(uint(session)), input, c.abi.ulongArgument(uint(len(plaintext))), output, length)
	})
}

func (c *Ctx) EncryptUpdate(session SessionHandle, plaintext []byte) ([]byte, error) {
	return c.inputOutput(functionEncryptUpdate, session, plaintext)
}

func (c *Ctx) EncryptFinal(session SessionHandle) ([]byte, error) {
	defer c.releaseMechanism(session, activeEncrypt)
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionEncryptFinal, c.abi.ulongArgument(uint(session)), output, length)
	})
}

func (c *Ctx) DecryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return err
	}
	return c.initializeMechanism(session, activeDecrypt, mechanism, func() uint {
		return c.call(functionDecryptInit,
			c.abi.ulongArgument(uint(session)), mechanism.pointer(), c.abi.ulongArgument(uint(key)))
	})
}

func (c *Ctx) Decrypt(session SessionHandle, ciphertext []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeDecrypt)
	return c.inputOutput(functionDecrypt, session, ciphertext)
}

func (c *Ctx) DecryptUpdate(session SessionHandle, ciphertext []byte) ([]byte, error) {
	return c.inputOutput(functionDecryptUpdate, session, ciphertext)
}

func (c *Ctx) DecryptFinal(session SessionHandle) ([]byte, error) {
	defer c.releaseMechanism(session, activeDecrypt)
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionDecryptFinal, c.abi.ulongArgument(uint(session)), output, length)
	})
}

func (c *Ctx) DigestInit(session SessionHandle, mechanisms []*Mechanism) error {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return err
	}
	return c.initializeMechanism(session, activeDigest, mechanism, func() uint {
		return c.call(functionDigestInit, c.abi.ulongArgument(uint(session)), mechanism.pointer())
	})
}

func (c *Ctx) Digest(session SessionHandle, data []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeDigest)
	return c.inputOutput(functionDigest, session, data)
}

func (c *Ctx) DigestUpdate(session SessionHandle, data []byte) error {
	return c.inputCall(functionDigestUpdate, session, data)
}

func (c *Ctx) DigestKey(session SessionHandle, key ObjectHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionDigestKey, c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(key))))
}

func (c *Ctx) DigestFinal(session SessionHandle) ([]byte, error) {
	defer c.releaseMechanism(session, activeDigest)
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionDigestFinal, c.abi.ulongArgument(uint(session)), output, length)
	})
}

func (c *Ctx) SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionSignInit, activeSign, session, mechanisms, key)
}

func (c *Ctx) Sign(session SessionHandle, data []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeSign)
	return c.inputOutput(functionSign, session, data)
}

func (c *Ctx) SignUpdate(session SessionHandle, data []byte) error {
	return c.inputCall(functionSignUpdate, session, data)
}

func (c *Ctx) SignFinal(session SessionHandle) ([]byte, error) {
	defer c.releaseMechanism(session, activeSign)
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionSignFinal, c.abi.ulongArgument(uint(session)), output, length)
	})
}

func (c *Ctx) SignRecoverInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionSignRecoverInit, activeSignRecover, session, mechanisms, key)
}

func (c *Ctx) SignRecover(session SessionHandle, data []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeSignRecover)
	return c.inputOutput(functionSignRecover, session, data)
}

func (c *Ctx) VerifyInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionVerifyInit, activeVerify, session, mechanisms, key)
}

func (c *Ctx) Verify(session SessionHandle, data, signature []byte) error {
	defer c.releaseMechanism(session, activeVerify)
	arena := &nativeArena{}
	defer arena.close()
	dataPointer, err := nativeCopy(arena, data)
	if err != nil {
		return err
	}
	signaturePointer, err := nativeCopy(arena, signature)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionVerify,
		c.abi.ulongArgument(uint(session)), dataPointer, c.abi.ulongArgument(uint(len(data))),
		signaturePointer, c.abi.ulongArgument(uint(len(signature)))))
}

func (c *Ctx) VerifyUpdate(session SessionHandle, data []byte) error {
	return c.inputCall(functionVerifyUpdate, session, data)
}

func (c *Ctx) VerifyFinal(session SessionHandle, signature []byte) error {
	defer c.releaseMechanism(session, activeVerify)
	return c.inputCall(functionVerifyFinal, session, signature)
}

func (c *Ctx) VerifyRecoverInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionVerifyRecoverInit, activeVerifyRecover, session, mechanisms, key)
}

func (c *Ctx) VerifyRecover(session SessionHandle, signature []byte) ([]byte, error) {
	defer c.releaseMechanism(session, activeVerifyRecover)
	return c.inputOutput(functionVerifyRecover, session, signature)
}

func (c *Ctx) DigestEncryptUpdate(session SessionHandle, data []byte) ([]byte, error) {
	return c.inputOutput(functionDigestEncryptUpdate, session, data)
}

func (c *Ctx) DecryptDigestUpdate(session SessionHandle, data []byte) ([]byte, error) {
	return c.inputOutput(functionDecryptDigestUpdate, session, data)
}

func (c *Ctx) SignEncryptUpdate(session SessionHandle, data []byte) ([]byte, error) {
	return c.inputOutput(functionSignEncryptUpdate, session, data)
}

func (c *Ctx) DecryptVerifyUpdate(session SessionHandle, data []byte) ([]byte, error) {
	return c.inputOutput(functionDecryptVerifyUpdate, session, data)
}

func (c *Ctx) mechanismKeyInit(id functionID, operation activeMechanismOperation, session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return err
	}
	return c.initializeMechanism(session, operation, mechanism, func() uint {
		return c.call(id,
			c.abi.ulongArgument(uint(session)), mechanism.pointer(), c.abi.ulongArgument(uint(key)))
	})
}

func (c *Ctx) inputCall(id functionID, session SessionHandle, input []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopy(arena, input)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(id, c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(len(input)))))
}

func (c *Ctx) inputOutput(id functionID, session SessionHandle, input []byte) ([]byte, error) {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopy(arena, input)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(id, c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(len(input))), output, length)
	})
}
