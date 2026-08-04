// Package vendorkit contains small helpers for implementing pkcs11.VendorModule
// outside the core driver.
//
// A provider whose integration is entirely declarative can use New or MustNew
// with a pkcs11.VendorDefinition. Providers that need custom mechanism,
// template, key-model, or operation behavior should define their own type,
// embed pkcs11.VendorBase, and override only the required methods.
package vendorkit

import (
	"fmt"

	pkcs11 "github.com/otpki/pkcs11"
)

// Module is an immutable, data-only VendorModule implementation.
//
// Module is appropriate when a provider needs only:
//   - fingerprint matching;
//   - module-discovery hints;
//   - proprietary numeric identifiers;
//   - low-level lifecycle, session, login, buffer, or recovery behavior; and
//   - conformance runtime metadata.
//
// It is not intended for providers that require custom route translation,
// object-template rewriting, nonstandard key models, or custom cryptographic
// execution. Those providers should implement pkcs11.VendorModule directly by
// embedding pkcs11.VendorBase.
//
// Module values are safe for concurrent use after construction. Definition
// returns an independent snapshot, so callers cannot mutate later discovery or
// client behavior through maps or slices in the returned value.
type Module struct {
	pkcs11.VendorBase
	definition pkcs11.VendorDefinition
}

// New validates definition and returns an immutable declarative vendor module.
// Validation uses the same rules as pkcs11.Config.Vendors, so an error returned
// here would otherwise be reported when a client or discovery operation starts.
func New(definition pkcs11.VendorDefinition) (*Module, error) {
	module := &Module{definition: pkcs11.CloneVendorDefinition(definition)}
	if _, err := pkcs11.VendorModules(module); err != nil {
		return nil, fmt.Errorf("vendorkit: invalid vendor definition: %w", err)
	}
	return module, nil
}

// MustNew is the package-initialization form of New. It panics when definition
// is invalid and is intended for static definitions compiled into a provider
// package, where an invalid definition is a programming error rather than a
// runtime configuration error.
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

// DecoratedModule wraps an existing VendorModule while replacing only its
// immutable definition. All operational hooks continue to dispatch to the
// wrapped module through interface promotion.
//
// This is useful for a consumer that has a licensed SDK and wants to add
// proprietary identifiers or local discovery paths without forking the
// provider's tested behavior implementation. Pass the decorated module instead
// of the original module; two modules with the same ID are rejected.
type DecoratedModule struct {
	pkcs11.VendorModule
	definition pkcs11.VendorDefinition
}

// Decorate clones base.Definition, calls update exactly once during
// construction, validates the result, and returns an immutable wrapper that
// delegates every operational method to base.
//
// The update function must change only static definition data. It cannot and
// should not alter session, route, or operation behavior; those remain methods
// on base. To change behavior, implement a normal VendorModule type instead.
func Decorate(base pkcs11.VendorModule, update func(*pkcs11.VendorDefinition)) (*DecoratedModule, error) {
	if base == nil {
		return nil, fmt.Errorf("vendorkit: base vendor module is nil")
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
