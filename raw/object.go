package raw

import (
	"errors"
	"fmt"
)

func tolerableAttributeRV(value uint) bool {
	return value == CKR_OK || value == CKR_ATTRIBUTE_SENSITIVE ||
		value == CKR_ATTRIBUTE_TYPE_INVALID || value == CKR_BUFFER_TOO_SMALL
}

func (c *Ctx) CreateObject(session SessionHandle, attributes []*Attribute) (ObjectHandle, error) {
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
	pointer, value, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionCreateObject,
		c.abi.ulongArgument(uint(session)), template.pointer(), c.abi.ulongArgument(template.count), pointer)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(value, 0)), nil
}

func (c *Ctx) CopyObject(session SessionHandle, object ObjectHandle, attributes []*Attribute) (ObjectHandle, error) {
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
	pointer, value, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionCopyObject,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object)),
		template.pointer(), c.abi.ulongArgument(template.count), pointer)); err != nil {
		return 0, err
	}
	return ObjectHandle(c.abi.getULong(value, 0)), nil
}

func (c *Ctx) DestroyObject(session SessionHandle, object ObjectHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionDestroyObject, c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object))))
}

func (c *Ctx) GetObjectSize(session SessionHandle, object ObjectHandle) (uint, error) {
	_, unlock, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	pointer, value, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return 0, err
	}
	if err := rv(c.call(functionGetObjectSize,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object)), pointer)); err != nil {
		return 0, err
	}
	return c.abi.getULong(value, 0), nil
}

// GetAttributeValue follows Cryptoki's two-call query convention. It returns
// all readable attributes even when the token also reports
// CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID.
func (c *Ctx) GetAttributeValue(session SessionHandle, object ObjectHandle, attributes []*Attribute) ([]*Attribute, error) {
	template, err := newGetTemplate(attributes)
	if err != nil {
		return nil, err
	}
	defer template.free()
	_, unlock, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()

	firstRV := c.call(functionGetAttributeValue,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object)),
		template.pointer(), c.abi.ulongArgument(template.count))
	if !tolerableAttributeRV(firstRV) {
		return nil, rv(firstRV)
	}
	if err := template.allocateGetValues(attributes); err != nil {
		return nil, err
	}
	secondRV := c.call(functionGetAttributeValue,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object)),
		template.pointer(), c.abi.ulongArgument(template.count))
	result := template.copyGetValues(attributes)
	if firstRV == CKR_OK && secondRV == CKR_OK {
		return result, nil
	}
	queryErr := &AttributeQueryError{}
	if firstRV != CKR_OK {
		queryErr.First = Error(firstRV)
	}
	if secondRV != CKR_OK {
		queryErr.Second = Error(secondRV)
	}
	return result, queryErr
}

func (c *Ctx) SetAttributeValue(session SessionHandle, object ObjectHandle, attributes []*Attribute) error {
	template, err := marshalTemplate(attributes)
	if err != nil {
		return err
	}
	defer template.free()
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionSetAttributeValue,
		c.abi.ulongArgument(uint(session)), c.abi.ulongArgument(uint(object)),
		template.pointer(), c.abi.ulongArgument(template.count)))
}

func (c *Ctx) FindObjectsInit(session SessionHandle, attributes []*Attribute) error {
	template, err := marshalTemplate(attributes)
	if err != nil {
		return err
	}
	defer template.free()
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionFindObjectsInit,
		c.abi.ulongArgument(uint(session)), template.pointer(), c.abi.ulongArgument(template.count)))
}

func (c *Ctx) FindObjects(session SessionHandle, maxObjects int) ([]ObjectHandle, bool, error) {
	if maxObjects < 1 {
		return nil, false, errors.New("pkcs11: max objects must be positive")
	}
	_, unlock, err := c.locked()
	if err != nil {
		return nil, false, err
	}
	defer unlock()
	arena := &nativeArena{}
	defer arena.close()
	total, err := checkedProduct(uint(maxObjects), uint(c.abi.ULongSize))
	if err != nil {
		return nil, false, err
	}
	objectsPointer, objects, err := nativeAlloc(arena, total)
	if err != nil {
		return nil, false, err
	}
	countPointer, countBytes, err := arena.alloc(c.abi.ULongSize)
	if err != nil {
		return nil, false, err
	}
	if err := rv(c.call(functionFindObjects,
		c.abi.ulongArgument(uint(session)), objectsPointer, c.abi.ulongArgument(uint(maxObjects)), countPointer)); err != nil {
		return nil, false, err
	}
	count := c.abi.getULong(countBytes, 0)
	if count > uint(maxObjects) {
		return nil, false, fmt.Errorf("pkcs11: module returned %d objects for a %d-object buffer", count, maxObjects)
	}
	result := make([]ObjectHandle, count)
	for index := range result {
		result[index] = ObjectHandle(c.abi.getULong(objects, index*c.abi.ULongSize))
	}
	return result, int(count) == maxObjects, nil
}

func (c *Ctx) FindObjectsFinal(session SessionHandle) error {
	_, unlock, err := c.locked()
	if err != nil {
		return err
	}
	defer unlock()
	return rv(c.call(functionFindObjectsFinal, c.abi.ulongArgument(uint(session))))
}

// FindAllObjects safely brackets a complete search with Init/Final.
func (c *Ctx) FindAllObjects(session SessionHandle, attributes []*Attribute, batchSize int) (objects []ObjectHandle, err error) {
	if batchSize <= 0 {
		batchSize = 64
	}
	if err = c.FindObjectsInit(session, attributes); err != nil {
		return nil, err
	}
	defer func() {
		if finalErr := c.FindObjectsFinal(session); err == nil && finalErr != nil {
			err = finalErr
		}
	}()
	for {
		batch, more, findErr := c.FindObjects(session, batchSize)
		objects = append(objects, batch...)
		if findErr != nil {
			return objects, findErr
		}
		if !more || len(batch) == 0 {
			return objects, nil
		}
	}
}
