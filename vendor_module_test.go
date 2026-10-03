package pkcs11

import (
	"context"
	"crypto"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// testVendorModule is a deliberately small programmable VendorModule used by
// root-package tests. Real provider behavior belongs in vendors/<provider>.
type testVendorModule struct {
	VendorBase
	definition         VendorDefinition
	adaptRoute         func(Device, Route) (Route, error)
	normalizeMechanism func(VendorMechanismContext, *raw.Mechanism) (*raw.Mechanism, error)
	normalizeTemplate  func(VendorTemplateContext, []*raw.Attribute) ([]*raw.Attribute, error)
	translateError     func(VendorErrorContext, error) error
	classifyError      func(VendorErrorContext, error) RecoveryAction
	objectAttributes   []uint
	inferAlgorithm     func(VendorObjectMetadata) (Algorithm, bool)
	keyPairModel       func(Algorithm, Route) (VendorKeyPairModel, bool)
	loadPublicKey      func(context.Context, VendorSession, ObjectRef, Algorithm) (crypto.PublicKey, bool, error)
}

func (m *testVendorModule) Definition() VendorDefinition { return m.definition }
func (m *testVendorModule) AdaptRoute(device Device, route Route) (Route, error) {
	if m.adaptRoute != nil {
		return m.adaptRoute(device, route)
	}
	return m.VendorBase.AdaptRoute(device, route)
}

func (m *testVendorModule) NormalizeMechanism(context VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
	if m.normalizeMechanism != nil {
		return m.normalizeMechanism(context, mechanism)
	}
	return m.VendorBase.NormalizeMechanism(context, mechanism)
}

func (m *testVendorModule) NormalizeTemplate(context VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	if m.normalizeTemplate != nil {
		return m.normalizeTemplate(context, attributes)
	}
	return m.VendorBase.NormalizeTemplate(context, attributes)
}

func (m *testVendorModule) TranslateError(context VendorErrorContext, err error) error {
	if m.translateError != nil {
		return m.translateError(context, err)
	}
	return m.VendorBase.TranslateError(context, err)
}

func (m *testVendorModule) ClassifyError(context VendorErrorContext, err error) RecoveryAction {
	if m.classifyError != nil {
		return m.classifyError(context, err)
	}
	return m.VendorBase.ClassifyError(context, err)
}

func (m *testVendorModule) ObjectAttributes() []uint {
	return slices.Clone(m.objectAttributes)
}

func (m *testVendorModule) InferAlgorithm(metadata VendorObjectMetadata) (Algorithm, bool) {
	if m.inferAlgorithm != nil {
		return m.inferAlgorithm(metadata)
	}
	return m.VendorBase.InferAlgorithm(metadata)
}

func (m *testVendorModule) KeyPairModel(algorithm Algorithm, route Route) (VendorKeyPairModel, bool) {
	if m.keyPairModel != nil {
		return m.keyPairModel(algorithm, route)
	}
	return m.VendorBase.KeyPairModel(algorithm, route)
}

func (m *testVendorModule) LoadPublicKey(ctx context.Context, session VendorSession, object ObjectRef, algorithm Algorithm) (crypto.PublicKey, bool, error) {
	if m.loadPublicKey != nil {
		return m.loadPublicKey(ctx, session, object, algorithm)
	}
	return m.VendorBase.LoadPublicKey(ctx, session, object, algorithm)
}

func newTestVendor(id AdapterFamily, name string, priority int, match VendorMatchSpec) *testVendorModule {
	return &testVendorModule{definition: VendorDefinition{
		ID: id, Name: name, Priority: priority, Source: "test",
		Match:   match,
		Catalog: VendorCatalog{Level: CatalogStandardOnly, Source: "test"},
	}}
}

func deviceForVendor(t interface {
	Helper()
	Fatal(...any)
}, module VendorModule, mechanisms map[raw.MechanismType]raw.MechanismInfo,
) Device {
	t.Helper()
	fp := Fingerprint{Token: raw.TokenInfo{Label: "test"}, Mechanisms: mechanisms}
	selection, err := selectAdapter(fp, CompatibilityConfig{AdapterFamily: module.Definition().ID}, []VendorModule{module})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := deriveCapabilities(fp, selection.definition)
	if selection.definition.module != nil {
		selection.definition.module.AugmentCapabilities(fp, &capabilities)
	}
	return Device{
		Fingerprint: fp, Adapter: selection.adapterInfo(), Capabilities: capabilities,
		definition: selection.definition, plan: selection.plan, vendor: selection.definition.module,
	}
}
