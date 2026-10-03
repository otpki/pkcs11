package raw

import (
	"errors"
	"fmt"
)

// Error is a CK_RV value returned by a PKCS#11 module.
type Error uint

func (e Error) Error() string {
	if name, ok := errorNames[uint(e)]; ok {
		return name
	}
	return fmt.Sprintf("CKR_0x%08x", uint(e))
}

func (e Error) Is(target error) bool {
	other, ok := errors.AsType[Error](target)
	return ok && e == other
}

// IsError reports whether err, including any wrapped or joined error, contains
// the specified CK_RV value.
func IsError(err error, value uint) bool {
	e, ok := errors.AsType[Error](err)
	return ok && uint(e) == value
}

func rv(value uint) error {
	if value == CKR_OK {
		return nil
	}
	return Error(value)
}
