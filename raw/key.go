package raw

import "slices"

func (c *Ctx) GenerateKey(session SessionHandle, mechanisms []*Mechanism, attributes []*Attribute) (ObjectHandle, error) {
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
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionGenerateKey,
		c.abi.ulongArgument(uint(session)), mechanism.pointer(),
		template.pointer(), c.abi.ulongArgument(template.count), keyPointer)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}

func (c *Ctx) GenerateKeyPair(session SessionHandle, mechanisms []*Mechanism, publicAttributes, privateAttributes []*Attribute) (ObjectHandle, ObjectHandle, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return 0, 0, err
	}
	defer mechanism.free()
	publicTemplate, err := marshalTemplate(publicAttributes)
	if err != nil {
		return 0, 0, err
	}
	defer publicTemplate.free()
	privateTemplate, err := marshalTemplate(privateAttributes)
	if err != nil {
		return 0, 0, err
	}
	defer privateTemplate.free()
	_, unlock, err := c.locked()
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	publicPointer, publicBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, 0, err
	}
	privatePointer, privateBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, 0, err
	}
	if err := rv(c.call(functionGenerateKeyPair,
		c.abi.ulongArgument(uint(session)), mechanism.pointer(),
		publicTemplate.pointer(), c.abi.ulongArgument(publicTemplate.count),
		privateTemplate.pointer(), c.abi.ulongArgument(privateTemplate.count),
		publicPointer, privatePointer)); err != nil {
		return 0, 0, err
	}
	return ObjectHandle(c.abi.getULong(publicBytes, 0)), ObjectHandle(c.abi.getULong(privateBytes, 0)), nil
}

func (c *Ctx) WrapKey(session SessionHandle, mechanisms []*Mechanism, wrappingKey, key ObjectHandle) ([]byte, error) {
	mechanism, err := onlyMechanism(mechanisms)
	if err != nil {
		return nil, err
	}
	defer mechanism.free()
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.callOutput(func(output, length uintptr) uint {
		return c.call(functionWrapKey,
			c.abi.ulongArgument(uint(session)), mechanism.pointer(),
			c.abi.ulongArgument(uint(wrappingKey)), c.abi.ulongArgument(uint(key)), output, length)
	})
}

func (c *Ctx) UnwrapKey(session SessionHandle, mechanisms []*Mechanism, unwrappingKey ObjectHandle, wrapped []byte, attributes []*Attribute) (ObjectHandle, error) {
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
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(functionUnwrapKey,
		c.abi.ulongArgument(uint(session)), mechanism.pointer(),
		c.abi.ulongArgument(uint(unwrappingKey)), wrappedPointer, c.abi.ulongArgument(uint(len(wrapped))),
		template.pointer(), c.abi.ulongArgument(template.count), keyPointer)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}

func (c *Ctx) DeriveKey(session SessionHandle, mechanisms []*Mechanism, baseKey ObjectHandle, attributes []*Attribute) (ObjectHandle, error) {
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
	keyPointer, keyBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := rv(c.call(functionDeriveKey,
		c.abi.ulongArgument(uint(session)), mechanism.pointer(), c.abi.ulongArgument(uint(baseKey)),
		template.pointer(), c.abi.ulongArgument(template.count), keyPointer)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(keyBytes, 0)), nil
}

func (c *Ctx) SeedRandom(session SessionHandle, seed []byte) error {
	arena := &nativeArena{}
	defer arena.close()
	pointer, err := nativeCopy(arena, seed)
	if err != nil {
		return err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionSeedRandom,
		c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(len(seed)))))
}

func (c *Ctx) GenerateRandom(session SessionHandle, length int) ([]byte, error) {
	if length < 0 {
		return nil, Error(CKR_ARGUMENTS_BAD)
	}
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(length)
	if err != nil {
		return nil, err
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := rv(c.call(functionGenerateRandom,
		c.abi.ulongArgument(uint(session)), pointer, c.abi.ulongArgument(uint(length)))); err != nil {
		return nil, err
	}
	return slices.Clone(value), nil
}
