package raw

func (c *Ctx) MessageEncryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionMessageEncryptInit, activeMessageEncrypt, session, mechanisms, key)
}

func (c *Ctx) EncryptMessage(session SessionHandle, parameter any, associatedData, plaintext []byte) ([]byte, error) {
	return c.messageCrypt(functionEncryptMessage, session, parameter, associatedData, plaintext)
}

func (c *Ctx) EncryptMessageBegin(session SessionHandle, parameter any, associatedData []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return err
	}
	defer metadata.sync()
	aadPointer, err := nativeCopy(arena, associatedData)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionEncryptMessageBegin,
		c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
		aadPointer, c.abi.ulongArgument(uint(len(associatedData)))))
}

func (c *Ctx) EncryptMessageNext(session SessionHandle, parameter any, plaintext []byte, flags uint) ([]byte, error) {
	return c.messageNext(functionEncryptMessageNext, session, parameter, plaintext, flags)
}

func (c *Ctx) MessageEncryptFinal(session SessionHandle) error {
	defer c.releaseMechanism(session, activeMessageEncrypt)
	return c.sessionOnlyCall(functionMessageEncryptFinal, session)
}

func (c *Ctx) MessageDecryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionMessageDecryptInit, activeMessageDecrypt, session, mechanisms, key)
}

func (c *Ctx) DecryptMessage(session SessionHandle, parameter any, associatedData, ciphertext []byte) ([]byte, error) {
	return c.messageCrypt(functionDecryptMessage, session, parameter, associatedData, ciphertext)
}

func (c *Ctx) DecryptMessageBegin(session SessionHandle, parameter any, associatedData []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return err
	}
	defer metadata.sync()
	aadPointer, err := nativeCopy(arena, associatedData)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionDecryptMessageBegin,
		c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
		aadPointer, c.abi.ulongArgument(uint(len(associatedData)))))
}

func (c *Ctx) DecryptMessageNext(session SessionHandle, parameter any, ciphertext []byte, flags uint) ([]byte, error) {
	return c.messageNext(functionDecryptMessageNext, session, parameter, ciphertext, flags)
}

func (c *Ctx) MessageDecryptFinal(session SessionHandle) error {
	defer c.releaseMechanism(session, activeMessageDecrypt)
	return c.sessionOnlyCall(functionMessageDecryptFinal, session)
}

func (c *Ctx) MessageSignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionMessageSignInit, activeMessageSign, session, mechanisms, key)
}

func (c *Ctx) SignMessage(session SessionHandle, parameter any, data []byte) ([]byte, error) {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return nil, err
	}
	defer metadata.sync()
	inputPointer, err := nativeCopy(arena, data)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionSignMessage,
			c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
			inputPointer, c.abi.ulongArgument(uint(len(data))), output, length)
	})
}

func (c *Ctx) SignMessageBegin(session SessionHandle, parameter any) error {
	return c.parameterSessionCall(functionSignMessageBegin, session, parameter)
}

func (c *Ctx) SignMessageNext(session SessionHandle, parameter any, data []byte) ([]byte, error) {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return nil, err
	}
	defer metadata.sync()
	inputPointer, err := nativeCopy(arena, data)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionSignMessageNext,
			c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
			inputPointer, c.abi.ulongArgument(uint(len(data))), output, length)
	})
}

func (c *Ctx) MessageSignFinal(session SessionHandle) error {
	defer c.releaseMechanism(session, activeMessageSign)
	return c.sessionOnlyCall(functionMessageSignFinal, session)
}

func (c *Ctx) MessageVerifyInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return c.mechanismKeyInit(functionMessageVerifyInit, activeMessageVerify, session, mechanisms, key)
}

func (c *Ctx) VerifyMessage(session SessionHandle, parameter any, data, signature []byte) error {
	return c.messageVerify(functionVerifyMessage, session, parameter, data, signature)
}

func (c *Ctx) VerifyMessageBegin(session SessionHandle, parameter any) error {
	return c.parameterSessionCall(functionVerifyMessageBegin, session, parameter)
}

func (c *Ctx) VerifyMessageNext(session SessionHandle, parameter any, data, signature []byte) error {
	return c.messageVerify(functionVerifyMessageNext, session, parameter, data, signature)
}

func (c *Ctx) MessageVerifyFinal(session SessionHandle) error {
	defer c.releaseMechanism(session, activeMessageVerify)
	return c.sessionOnlyCall(functionMessageVerifyFinal, session)
}

func (c *Ctx) messageCrypt(id functionID, session SessionHandle, parameter any, associatedData, input []byte) ([]byte, error) {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return nil, err
	}
	defer metadata.sync()
	aadPointer, err := nativeCopy(arena, associatedData)
	if err != nil {
		return nil, err
	}
	inputPointer, err := nativeCopy(arena, input)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(id,
			c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
			aadPointer, c.abi.ulongArgument(uint(len(associatedData))),
			inputPointer, c.abi.ulongArgument(uint(len(input))), output, length)
	})
}

func (c *Ctx) messageNext(id functionID, session SessionHandle, parameter any, input []byte, flags uint) ([]byte, error) {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return nil, err
	}
	defer metadata.sync()
	inputPointer, err := nativeCopy(arena, input)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(id,
			c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
			inputPointer, c.abi.ulongArgument(uint(len(input))), output, length, c.abi.ulongArgument(flags))
	})
}

func (c *Ctx) messageVerify(id functionID, session SessionHandle, parameter any, data, signature []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return err
	}
	defer metadata.sync()
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
	return rv(c.call(id,
		c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength),
		dataPointer, c.abi.ulongArgument(uint(len(data))), signaturePointer, c.abi.ulongArgument(uint(len(signature)))))
}

func (c *Ctx) parameterSessionCall(id functionID, session SessionHandle, parameter any) error {
	arena := &nativeArena{}
	defer arena.close()
	parameterPointer, parameterLength, metadata, err := marshalParameterInto(arena, parameter)
	if err != nil {
		return err
	}
	defer metadata.sync()
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(id, c.abi.ulongArgument(uint(session)), parameterPointer, c.abi.ulongArgument(parameterLength)))
}

func (c *Ctx) sessionOnlyCall(id functionID, session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(id, c.abi.ulongArgument(uint(session))))
}
