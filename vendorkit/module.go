// Package vendorkit contains helpers for implementing pkcs11.VendorModule.
// Declarative providers can use New or MustNew with a VendorDefinition.
// Providers with custom behavior should embed pkcs11.VendorBase in their own
// type and override the hooks they need.
package vendorkit

import (
	"errors"
	"fmt"

	pkcs11 "github.com/otpki/pkcs11"
)

// Module is an immutable VendorModule backed only by VendorDefinition data.
// Use it for matching, discovery hints, proprietary IDs, behavior flags, and
// conformance metadata. Providers that need custom runtime hooks should embed
// pkcs11.VendorBase in their own type instead.
//
// Module is safe for concurrent use and Definition returns a defensive copy.
type Module struct {
	pkcs11.VendorBase
	definition pkcs11.VendorDefinition
}

// New validates definition and returns an immutable declarative vendor module.
func New(definition pkcs11.VendorDefinition) (*Module, error) {
	module := &Module{definition: pkcs11.CloneVendorDefinition(definition)}
	if _, err := pkcs11.VendorModules(module); err != nil {
		return nil, fmt.Errorf("vendorkit: invalid vendor definition: %w", err)
	}
	return module, nil
}

// MustNew is New for static package definitions. It panics on invalid input.
func MustNew(definition pkcs11.VendorDefinition) *Module {
	module, err := New(definition)
	if err != nil {
		panic(err)
	}
	return module
}

// Definition implements pkcs11.VendorModule. The returned value is a defensive
// copy; mutating it has no effect on this module or on clients opened later.
func (m *Module) Definition() pkcs11.VendorDefinition {
	if m == nil {
		return pkcs11.VendorDefinition{}
	}
	return pkcs11.CloneVendorDefinition(m.definition)
}

// DecoratedModule wraps a VendorModule with a different static definition.
// Runtime hooks still come from the wrapped module. This is useful for adding
// local IDs or discovery hints without forking provider behavior.
type DecoratedModule struct {
	pkcs11.VendorModule
	definition pkcs11.VendorDefinition
}

// Decorate copies base.Definition, applies update once, validates it, and
// returns a wrapper. update should only change static definition data.
func Decorate(base pkcs11.VendorModule, update func(*pkcs11.VendorDefinition)) (*DecoratedModule, error) {
	if base == nil {
		return nil, errors.New("vendorkit: base vendor module is nil")
	}
	definition := pkcs11.CloneVendorDefinition(base.Definition())
	if update != nil {
		update(&definition)
	}
	module := &DecoratedModule{VendorModule: base, definition: pkcs11.CloneVendorDefinition(definition)}
	if _, err := pkcs11.VendorModules(module); err != nil {
		return nil, fmt.Errorf("vendorkit: invalid decorated vendor definition: %w", err)
	}
	return module, nil
}

// MustDecorate is the package-initialization form of Decorate. It panics when
// the decorated definition is invalid.
func MustDecorate(base pkcs11.VendorModule, update func(*pkcs11.VendorDefinition)) *DecoratedModule {
	module, err := Decorate(base, update)
	if err != nil {
		panic(err)
	}
	return module
}

// Definition implements pkcs11.VendorModule and returns a defensive snapshot
// of the decorated definition.
func (m *DecoratedModule) Definition() pkcs11.VendorDefinition {
	if m == nil {
		return pkcs11.VendorDefinition{}
	}
	return pkcs11.CloneVendorDefinition(m.definition)
}
