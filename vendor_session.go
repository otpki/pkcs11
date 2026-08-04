package pkcs11

import (
	"context"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// Call implements VendorSession. The raw handle never escapes the callback and
// the call retains normal tracing, serialization, thread affinity, and broken-
// session classification.
func (s *sessionLease) Call(ctx context.Context, operation string, fn func(raw.Module, raw.SessionHandle) error) error {
	if s == nil {
		return fmt.Errorf("pkcs11: vendor session is closed")
	}
	if fn == nil {
		return fmt.Errorf("pkcs11: nil vendor raw callback")
	}
	if operation == "" {
		operation = "vendor-operation"
	}
	return s.callContext(ctx, operation, func(module raw.Module) error {
		return fn(module, s.handle)
	})
}

// Resolve implements VendorSession using the same durable-locator and cache
// rules as the high-level driver.
func (s *sessionLease) Resolve(object ObjectRef) (raw.ObjectHandle, error) {
	if s == nil {
		return 0, fmt.Errorf("pkcs11: vendor session is closed")
	}
	return resolveObject(s, object)
}

// InvalidateObjects implements VendorSession after a vendor operation mutates
// token or session objects in a way the root driver cannot infer precisely.
func (s *sessionLease) InvalidateObjects() {
	if s != nil {
		s.invalidateCache()
	}
}
