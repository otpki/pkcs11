package pkcs11

import (
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

func cloneMechanism(mechanism *raw.Mechanism) *raw.Mechanism {
	if mechanism == nil {
		return nil
	}
	return &raw.Mechanism{Mechanism: mechanism.Mechanism, Parameter: cloneMechanismParameter(mechanism.Parameter)}
}

// cloneMechanismParameter protects caller-owned slices and typed parameter
// structs before a VendorModule is allowed to normalize them. Arbitrary custom
// marshalers are treated as immutable; implementations that carry mutable
// state should return a fresh value from the application or vendor module.
func cloneMechanismParameter(parameter any) any {
	switch value := parameter.(type) {
	case []byte:
		return append([]byte(nil), value...)
	case raw.OAEPParams:
		value.SourceData = append([]byte(nil), value.SourceData...)
		return value
	case *raw.OAEPParams:
		if value == nil {
			return (*raw.OAEPParams)(nil)
		}
		copied := *value
		copied.SourceData = append([]byte(nil), value.SourceData...)
		return &copied
	case raw.GCMParams:
		value.IV = append([]byte(nil), value.IV...)
		value.AAD = append([]byte(nil), value.AAD...)
		return value
	case *raw.GCMParams:
		if value == nil {
			return (*raw.GCMParams)(nil)
		}
		copied := *value
		copied.IV = append([]byte(nil), value.IV...)
		copied.AAD = append([]byte(nil), value.AAD...)
		return &copied
	case raw.ECDH1DeriveParams:
		value.SharedData = append([]byte(nil), value.SharedData...)
		value.PublicData = append([]byte(nil), value.PublicData...)
		return value
	case *raw.ECDH1DeriveParams:
		if value == nil {
			return (*raw.ECDH1DeriveParams)(nil)
		}
		copied := *value
		copied.SharedData = append([]byte(nil), value.SharedData...)
		copied.PublicData = append([]byte(nil), value.PublicData...)
		return &copied
	case raw.EdDSAParams:
		value.Context = append([]byte(nil), value.Context...)
		return value
	case *raw.EdDSAParams:
		if value == nil {
			return (*raw.EdDSAParams)(nil)
		}
		copied := *value
		copied.Context = append([]byte(nil), value.Context...)
		return &copied
	case raw.SignAdditionalContext:
		value.Context = append([]byte(nil), value.Context...)
		return value
	case *raw.SignAdditionalContext:
		if value == nil {
			return (*raw.SignAdditionalContext)(nil)
		}
		copied := *value
		copied.Context = append([]byte(nil), value.Context...)
		return &copied
	case raw.HashSignAdditionalContext:
		value.Context = append([]byte(nil), value.Context...)
		return value
	case *raw.HashSignAdditionalContext:
		if value == nil {
			return (*raw.HashSignAdditionalContext)(nil)
		}
		copied := *value
		copied.Context = append([]byte(nil), value.Context...)
		return &copied
	default:
		return parameter
	}
}

func mechanismAdvertised(device Device, mechanism uint) bool {
	_, ok := device.Fingerprint.Mechanisms[raw.MechanismType(mechanism)]
	return ok
}

// normalizeVendorMechanism delegates provider-specific ABI translation to the
// selected VendorModule. The root passes a private copy so the module cannot
// mutate caller-owned route state.
func normalizeVendorMechanism(device Device, operation string, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
	if mechanism == nil {
		return nil, fmt.Errorf("pkcs11: nil mechanism for %s", operation)
	}
	if device.vendor == nil {
		return cloneMechanism(mechanism), nil
	}
	return device.vendor.NormalizeMechanism(
		VendorMechanismContext{Device: cloneDevice(device), Operation: operation},
		cloneMechanism(mechanism),
	)
}

func normalizeVendorMechanisms(device Device, operation string, mechanisms []*raw.Mechanism) ([]*raw.Mechanism, error) {
	result := make([]*raw.Mechanism, len(mechanisms))
	for i, mechanism := range mechanisms {
		adapted, err := normalizeVendorMechanism(device, operation, mechanism)
		if err != nil {
			return nil, err
		}
		result[i] = adapted
	}
	return result, nil
}

func attributeULong(attributes []*raw.Attribute, typ uint) (uint, bool) {
	for _, attribute := range attributes {
		if attribute == nil || attribute.Type != typ {
			continue
		}
		value, ok := raw.ULong(attribute.Value)
		return value, ok
	}
	return 0, false
}

// AttributeULong returns one native-width unsigned attribute value. It is
// exported for vendor modules that need to inspect a copied template.
func AttributeULong(attributes []*raw.Attribute, typ uint) (uint, bool) {
	return attributeULong(attributes, typ)
}

func removeAttributes(attributes []*raw.Attribute, types ...uint) []*raw.Attribute {
	remove := make(map[uint]struct{}, len(types))
	for _, typ := range types {
		remove[typ] = struct{}{}
	}
	result := make([]*raw.Attribute, 0, len(attributes))
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}
		if _, ok := remove[attribute.Type]; ok {
			continue
		}
		result = append(result, attribute)
	}
	return result
}

// RemoveAttributes returns a copy of attributes without the listed types.
func RemoveAttributes(attributes []*raw.Attribute, types ...uint) []*raw.Attribute {
	return removeAttributes(cloneAttributeTemplate(attributes), types...)
}

// MergeAttributes merges templates by type. Later values replace earlier ones
// while preserving the first-seen attribute order. All values are cloned.
func MergeAttributes(groups ...[]*raw.Attribute) []*raw.Attribute {
	return mergeAttributes(groups...)
}

// CloneAttributes returns a deep copy of a possibly nested PKCS #11 template.
func CloneAttributes(attributes []*raw.Attribute) []*raw.Attribute {
	return cloneAttributeTemplate(attributes)
}

// normalizeVendorTemplate delegates provider object-model compatibility to the
// selected VendorModule after making a deep copy of the standard template.
func normalizeVendorTemplate(device Device, operation string, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	result := cloneAttributeTemplate(attributes)
	if device.vendor == nil {
		return result, nil
	}
	return device.vendor.NormalizeTemplate(
		VendorTemplateContext{Device: cloneDevice(device), Operation: operation},
		result,
	)
}

func classifyVendorError(device Device, err error, retryGeneral bool) RecoveryAction {
	standard := ClassifyError(err, retryGeneral)
	if device.vendor == nil {
		return standard
	}
	action := device.vendor.ClassifyError(
		VendorErrorContext{Device: cloneDevice(device), StandardAction: standard, RetryGeneral: retryGeneral},
		err,
	)
	if standard != RecoveryNone && action < standard {
		return standard
	}
	if action == RecoveryNone {
		return standard
	}
	return action
}
