package raw

import "fmt"

// EncapsulateKey implements PKCS #11 3.2 C_EncapsulateKey and returns both
// the KEM ciphertext and the newly-created shared-secret object.
func (c *Ctx) EncapsulateKey(session SessionHandle, mechanisms []*Mechanism, publicKey ObjectHandle, attributes []*Attribute) ([]byte, ObjectHandle, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return nil, 0, err
	}
	defer mechanism.free()
	template, err := marshalTemplate(attributes)
	if err != nil {
		return nil, 0, err
	}
	defer template.free()

	arena := &nativeArena{}
	defer arena.close()
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return nil, 0, err
	}

	_, unlock, err := c.locked()
	if err != nil {
		return nil, 0, err
	}
	defer unlock()

	ciphertext, err := c.callOutput(func(output, length uintptr) uint {
		return c.call(
			functionEncapsulateKey,
			c.abi.ulongArgument(uint(session)),
			mechanism.pointer(),
			c.abi.ulongArgument(uint(publicKey)),
			template.pointer(),
			c.abi.ulongArgument(template.count),
			output,
			length,
			keyPointer,
		)
	})
	if err != nil {
		return nil, 0, err
	}
	return ciphertext, ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}

// DecapsulateKey implements PKCS #11 3.2 C_DecapsulateKey and returns the
// handle of the newly-created shared-secret object.
func (c *Ctx) DecapsulateKey(session SessionHandle, mechanisms []*Mechanism, privateKey ObjectHandle, ciphertext []byte, attributes []*Attribute) (ObjectHandle, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return 0, err
	}
	defer mechanism.free()
	template, err := marshalTemplate(attributes)
	if err != nil {
		return 0, err
	}
	defer template.free()

	arena := &nativeArena{}
	defer arena.close()
	ciphertextPointer, err := nativeCopy(arena, ciphertext)
	if err != nil {
		return 0, err
	}
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}

	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(
		functionDecapsulateKey,
		c.abi.ulongArgument(uint(session)),
		mechanism.pointer(),
		c.abi.ulongArgument(uint(privateKey)),
		template.pointer(),
		c.abi.ulongArgument(template.count),
		ciphertextPointer,
		c.abi.ulongArgument(uint(len(ciphertext))),
		keyPointer,
	)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}

// VerifySignatureInit starts the PKCS #11 3.2 signature-first verification
// flow. This is distinct from the classic C_VerifyInit/C_Verify API.
func (c *Ctx) VerifySignatureInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle, signature []byte) error {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return err
	}
	// Keep the signature bytes in the same retained arena as the mechanism.
	// A conforming provider should consume them during Init, but retaining the
	// complete initialization frame is safer for middleware that defers parsing
	// until C_VerifySignature or C_VerifySignatureFinal.
	signaturePointer, _, err := mechanism.arena.copy(signature)
	if err != nil {
		mechanism.free()
		return err
	}
	return c.initializeMechanism(session, activeVerifySignature, mechanism, func() uint {
		return c.call(
			functionVerifySignatureInit,
			c.abi.ulongArgument(uint(session)),
			mechanism.pointer(),
			c.abi.ulongArgument(uint(key)),
			signaturePointer,
			c.abi.ulongArgument(uint(len(signature))),
		)
	})
}

// VerifySignature supplies the complete data value to the PKCS #11 3.2
// signature-first verification operation started by VerifySignatureInit.
func (c *Ctx) VerifySignature(session SessionHandle, data []byte) error {
	defer c.releaseMechanism(session, activeVerifySignature)
	return c.inputCall(functionVerifySignature, session, data)
}

// VerifySignatureUpdate supplies another data part to a multipart PKCS #11
// 3.2 signature-first verification operation.
func (c *Ctx) VerifySignatureUpdate(session SessionHandle, data []byte) error {
	return c.inputCall(functionVerifySignatureUpdate, session, data)
}

// VerifySignatureFinal completes multipart signature-first verification.
func (c *Ctx) VerifySignatureFinal(session SessionHandle) error {
	defer c.releaseMechanism(session, activeVerifySignature)
	return c.sessionOnlyCall(functionVerifySignatureFinal, session)
}

// GetSessionValidationFlags returns the PKCS #11 3.2 validation flags for typ.
func (c *Ctx) GetSessionValidationFlags(session SessionHandle, typ ValidationFlagsType) (Flags, error) {
	arena := &nativeArena{}
	defer arena.close()
	flagsPointer, flagsBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(
		functionGetSessionValidationFlags,
		c.abi.ulongArgument(uint(session)),
		c.abi.ulongArgument(uint(typ)),
		flagsPointer,
	)); err != nil {
		return 0, err
	}
	return Flags(c.abi.getULong(flagsBytes, 0)), nil
}

type asyncDataLayout struct {
	version, value, scalar, object, additionalObject, size int
}

func nativeAsyncDataLayout(abi NativeABI) asyncDataLayout {
	builder := newNativeLayoutBuilder(abi)
	layout := asyncDataLayout{}
	layout.version = builder.addULong()
	layout.value = builder.addPointer()
	layout.scalar = builder.addULong()
	layout.object = builder.addULong()
	layout.additionalObject = builder.addULong()
	layout.size = builder.size()
	return layout
}

func nativeFunctionName(arena *nativeArena, functionName string) (uintptr, error) {
	pointer, _, err := arena.copy(append([]byte(functionName), 0))
	return pointer, err
}

// AsyncComplete exposes C_AsyncComplete without guessing the result layout for
// a particular asynchronous function. Value is used as the caller-provided
// buffer; Scalar, Object, and AdditionalObject map directly to CK_ASYNC_DATA.
func (c *Ctx) AsyncComplete(session SessionHandle, functionName string, result *AsyncData) error {
	if result == nil {
		return fmt.Errorf("pkcs11: nil async result")
	}
	arena := &nativeArena{}
	defer arena.close()
	namePointer, err := nativeFunctionName(arena, functionName)
	if err != nil {
		return err
	}
	valuePointer, valueBytes, err := arena.copy(result.Value)
	if err != nil {
		return err
	}
	valueLength := result.Scalar
	if valueLength == 0 && len(result.Value) > 0 {
		valueLength = uint(len(result.Value))
	}
	layout := nativeAsyncDataLayout(c.abi)
	resultPointer, resultBytes, err := arena.alloc(layout.size)
	if err != nil {
		return err
	}
	c.abi.putULong(resultBytes, layout.version, result.Version)
	c.abi.putPointer(resultBytes, layout.value, valuePointer)
	c.abi.putULong(resultBytes, layout.scalar, valueLength)
	c.abi.putULong(resultBytes, layout.object, uint(result.Object))
	c.abi.putULong(resultBytes, layout.additionalObject, uint(result.AdditionalObject))

	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	if err := rv(c.call(
		functionAsyncComplete,
		c.abi.ulongArgument(uint(session)),
		namePointer,
		resultPointer,
	)); err != nil {
		return err
	}

	result.Version = c.abi.getULong(resultBytes, layout.version)
	result.Scalar = c.abi.getULong(resultBytes, layout.scalar)
	result.Object = ObjectHandle(c.abi.getULong(resultBytes, layout.object))
	result.AdditionalObject = ObjectHandle(c.abi.getULong(resultBytes, layout.additionalObject))
	if len(valueBytes) != 0 {
		length := min(result.Scalar, uint(len(valueBytes)))
		result.Value = append(result.Value[:0], valueBytes[:length]...)
	}
	return nil
}

// AsyncGetID returns the persistent identifier assigned to an asynchronous
// operation for functionName.
func (c *Ctx) AsyncGetID(session SessionHandle, functionName string) (uint, error) {
	arena := &nativeArena{}
	defer arena.close()
	namePointer, err := nativeFunctionName(arena, functionName)
	if err != nil {
		return 0, err
	}
	idPointer, idBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(
		functionAsyncGetID,
		c.abi.ulongArgument(uint(session)),
		namePointer,
		idPointer,
	)); err != nil {
		return 0, err
	}
	return c.abi.getULong(idBytes, 0), nil
}

// AsyncJoin supplies data used to join the asynchronous operation identified
// by id for functionName.
func (c *Ctx) AsyncJoin(session SessionHandle, functionName string, id uint, data []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	namePointer, err := nativeFunctionName(arena, functionName)
	if err != nil {
		return err
	}
	dataPointer, err := nativeCopy(arena, data)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(
		functionAsyncJoin,
		c.abi.ulongArgument(uint(session)),
		namePointer,
		c.abi.ulongArgument(id),
		dataPointer,
		c.abi.ulongArgument(uint(len(data))),
	))
}

// WrapKeyAuthenticated implements PKCS #11 3.2 authenticated key wrapping.
func (c *Ctx) WrapKeyAuthenticated(session SessionHandle, mechanisms []*Mechanism, wrappingKey, key ObjectHandle, associatedData []byte) ([]byte, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return nil, err
	}
	defer mechanism.free()
	arena := &nativeArena{}
	defer arena.close()
	aadPointer, err := nativeCopy(arena, associatedData)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(
			functionWrapKeyAuthenticated,
			c.abi.ulongArgument(uint(session)),
			mechanism.pointer(),
			c.abi.ulongArgument(uint(wrappingKey)),
			c.abi.ulongArgument(uint(key)),
			aadPointer,
			c.abi.ulongArgument(uint(len(associatedData))),
			output,
			length,
		)
	})
}

// UnwrapKeyAuthenticated implements PKCS #11 3.2 authenticated key unwrapping.
func (c *Ctx) UnwrapKeyAuthenticated(session SessionHandle, mechanisms []*Mechanism, unwrappingKey ObjectHandle, wrapped []byte, attributes []*Attribute, associatedData []byte) (ObjectHandle, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return 0, err
	}
	defer mechanism.free()
	template, err := marshalTemplate(attributes)
	if err != nil {
		return 0, err
	}
	defer template.free()
	arena := &nativeArena{}
	defer arena.close()
	wrappedPointer, err := nativeCopy(arena, wrapped)
	if err != nil {
		return 0, err
	}
	aadPointer, err := nativeCopy(arena, associatedData)
	if err != nil {
		return 0, err
	}
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(
		functionUnwrapKeyAuthenticated,
		c.abi.ulongArgument(uint(session)),
		mechanism.pointer(),
		c.abi.ulongArgument(uint(unwrappingKey)),
		wrappedPointer,
		c.abi.ulongArgument(uint(len(wrapped))),
		template.pointer(),
		c.abi.ulongArgument(template.count),
		aadPointer,
		c.abi.ulongArgument(uint(len(associatedData))),
		keyPointer,
	)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}
