package raw

import (
	"errors"
	"fmt"
)

// AttributeQueryError reports a PKCS#11 return value that applies to an
// attribute query as a whole. Per-attribute unavailable/sensitive values are
// represented by a nil Value in the returned Attribute slice.
type AttributeQueryError struct {
	First  error
	Second error
}

func (e *AttributeQueryError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.First == nil:
		return e.Second.Error()
	case e.Second == nil || errors.Is(e.Second, e.First):
		return e.First.Error()
	default:
		return fmt.Sprintf("%v; second attribute read: %v", e.First, e.Second)
	}
}

func (e *AttributeQueryError) Unwrap() []error {
	if e == nil {
		return nil
	}
	var out []error
	if e.First != nil {
		out = append(out, e.First)
	}
	if e.Second != nil {
		out = append(out, e.Second)
	}
	return out
}
