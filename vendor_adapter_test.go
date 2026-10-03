package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

func TestVendorNormalizationIsDelegatedWithoutMutatingCallerValues(t *testing.T) {
	const vendorMechanism = 0x80001000
	module := newTestVendor("normalizer", "Normalizer", 1, VendorMatchSpec{Manufacturers: []string{"normalizer"}})
	module.normalizeMechanism = func(context VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
		if context.Operation != "C_EncryptInit" {
			t.Fatalf("operation = %q", context.Operation)
		}
		mechanism.Mechanism = vendorMechanism
		return mechanism, nil
	}
	module.normalizeTemplate = func(_ VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
		return MergeAttributes(attributes, []*raw.Attribute{raw.NewAttribute(raw.CKA_DERIVE, true)}), nil
	}
	device := deviceForVendor(t, module, nil)
	originalMechanism := raw.NewMechanism(raw.CKM_AES_GCM, raw.GCMParams{IV: []byte{1, 2, 3}})
	adapted, err := normalizeVendorMechanism(device, "C_EncryptInit", originalMechanism)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Mechanism != vendorMechanism || originalMechanism.Mechanism != raw.CKM_AES_GCM {
		t.Fatalf("adapted=%#v original=%#v", adapted, originalMechanism)
	}
	originalTemplate := []*raw.Attribute{raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY)}
	adaptedTemplate, err := normalizeVendorTemplate(device, "C_GenerateKeyPair/private", originalTemplate)
	if err != nil {
		t.Fatal(err)
	}
	derive := false
	for _, attribute := range adaptedTemplate {
		if attribute != nil && attribute.Type == raw.CKA_DERIVE {
			derive, _ = raw.Bool(attribute.Value)
		}
	}
	if !derive || len(originalTemplate) != 1 {
		t.Fatalf("adapted=%#v original=%#v", adaptedTemplate, originalTemplate)
	}
}

func TestVendorErrorClassifierCannotWeakenStandardRecovery(t *testing.T) {
	module := newTestVendor("classifier", "Classifier", 1, VendorMatchSpec{Manufacturers: []string{"classifier"}})
	module.classifyError = func(context VendorErrorContext, _ error) RecoveryAction {
		if context.StandardAction != RecoveryReinitialize {
			t.Fatalf("standard action = %v", context.StandardAction)
		}
		return RecoveryNone
	}
	device := deviceForVendor(t, module, nil)
	if got := classifyVendorError(device, raw.Error(raw.CKR_DEVICE_ERROR), false); got != RecoveryReinitialize {
		t.Fatalf("action = %v, want reinitialize", got)
	}
}

func TestVendorErrorClassifierMayStrengthenUnknownErrors(t *testing.T) {
	module := newTestVendor("classifier", "Classifier", 1, VendorMatchSpec{Manufacturers: []string{"classifier"}})
	module.classifyError = func(context VendorErrorContext, _ error) RecoveryAction {
		if context.StandardAction != RecoveryNone {
			t.Fatalf("standard action = %v", context.StandardAction)
		}
		return RecoveryReplaceSession
	}
	device := deviceForVendor(t, module, nil)
	if got := classifyVendorError(device, errors.New("vendor transport reset"), false); got != RecoveryReplaceSession {
		t.Fatalf("action = %v", got)
	}
}

const (
	testVendorErrNotLoggedIn = 0x8000000C
	testVendorErrUnreachable = 0x80005015
)

func TestVendorBaseTranslateErrorReturnsInput(t *testing.T) {
	var base VendorBase
	vendor := raw.Error(testVendorErrNotLoggedIn)
	if got := base.TranslateError(VendorErrorContext{}, vendor); !errors.Is(got, error(vendor)) {
		t.Fatalf("TranslateError = %v, want unchanged vendor error", got)
	}
	if got := base.TranslateError(VendorErrorContext{}, nil); got != nil {
		t.Fatalf("TranslateError(nil) = %v, want nil", got)
	}
}

func TestTranslatedVendorErrorExposesStandardValueAndPreservesOriginal(t *testing.T) {
	original := raw.Error(testVendorErrNotLoggedIn)
	err := TranslateVendorError(original, raw.CKR_USER_NOT_LOGGED_IN)

	if !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("IsError(CKR_USER_NOT_LOGGED_IN) = false for %v", err)
	}
	// The vendor value must not win primary raw.Error resolution.
	if raw.IsError(err, testVendorErrNotLoggedIn) {
		t.Fatal("vendor value must not shadow the standard result in IsError")
	}
	if got, ok := errors.AsType[raw.Error](err); !ok || got != raw.Error(raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("errors.AsType[raw.Error] = %v,%v, want CKR_USER_NOT_LOGGED_IN", got, ok)
	}
	// The original vendor error stays reachable for diagnostics.
	if !errors.Is(err, original) {
		t.Fatal("errors.Is lost the original vendor error")
	}
	translated, ok := errors.AsType[*TranslatedVendorError](err)
	if !ok || !errors.Is(translated.Original, original) {
		t.Fatalf("errors.As(*TranslatedVendorError) = %v", translated)
	}
	if got, want := err.Error(), "CKR_USER_NOT_LOGGED_IN (vendor 0x8000000C)"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if got := TranslateVendorError(nil, raw.CKR_USER_NOT_LOGGED_IN); got != nil {
		t.Fatalf("TranslateVendorError(nil) = %v, want nil", got)
	}
}

func TestTranslatedVendorErrorFormatsWrappedAndNonVendorOriginals(t *testing.T) {
	wrapped := TranslateVendorError(
		fmt.Errorf("C_GetObjectSize: %w", raw.Error(testVendorErrUnreachable)), raw.CKR_DEVICE_ERROR)
	if got, want := wrapped.Error(), "CKR_DEVICE_ERROR (vendor 0x80005015)"; got != want {
		t.Fatalf("wrapped message = %q, want %q", got, want)
	}
	nonRV := TranslateVendorError(errors.New("vendor transport refused"), raw.CKR_DEVICE_ERROR)
	if got, want := nonRV.Error(), "CKR_DEVICE_ERROR (vendor error: vendor transport refused)"; got != want {
		t.Fatalf("non-RV message = %q, want %q", got, want)
	}
	translated, ok := errors.AsType[*TranslatedVendorError](nonRV)
	if !ok || translated.Original == nil {
		t.Fatal("errors.As cannot reach TranslatedVendorError.Original")
	}
}

// translateRecorder records what recovery classification observes to prove
// translation ran first.
type translateRecorder struct {
	actions []RecoveryAction
	seen    []error
}

func newTranslatingVendor(recorder *translateRecorder) *testVendorModule {
	module := newTestVendor("translator", "Translator", 1, VendorMatchSpec{Manufacturers: []string{"translator"}})
	module.translateError = func(_ VendorErrorContext, err error) error {
		code, ok := errors.AsType[raw.Error](err)
		if !ok {
			return err
		}
		switch uint(code) {
		case testVendorErrNotLoggedIn:
			return TranslateVendorError(err, raw.CKR_USER_NOT_LOGGED_IN)
		case testVendorErrUnreachable:
			return TranslateVendorError(err, raw.CKR_DEVICE_ERROR)
		}
		return err
	}
	module.classifyError = func(context VendorErrorContext, err error) RecoveryAction {
		recorder.actions = append(recorder.actions, context.StandardAction)
		recorder.seen = append(recorder.seen, err)
		return context.StandardAction
	}
	return module
}

func translatingPool(t *testing.T, module *testVendorModule) *sessionPool {
	t.Helper()
	return &sessionPool{
		module: &moduleRef{raw: testmock.New("translate", 1)},
		device: deviceForVendor(t, module, nil),
	}
}

func TestSessionLeaseCallTranslatesBeforeClassification(t *testing.T) {
	recorder := &translateRecorder{}
	module := newTranslatingVendor(recorder)
	lease := &sessionLease{pool: translatingPool(t, module), handle: 1}

	err := lease.call(context.Background(), "C_GetObjectSize", func(raw.Module) error {
		return raw.Error(testVendorErrNotLoggedIn)
	})
	if !raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) {
		t.Fatalf("call error = %v, want translated CKR_USER_NOT_LOGGED_IN", err)
	}
	if len(recorder.seen) != 1 {
		t.Fatalf("classifier observations = %d, want 1", len(recorder.seen))
	}
	if !raw.IsError(recorder.seen[0], raw.CKR_USER_NOT_LOGGED_IN) || recorder.actions[0] != RecoveryRelogin {
		t.Fatalf("classifier saw %v with action %v, want translated error + RecoveryRelogin",
			recorder.seen[0], recorder.actions[0])
	}
	if !lease.broken.Load() {
		t.Fatal("relogin-classified error must mark the session broken")
	}
}

func TestSessionLeaseDoRawTranslatesBeforeClassification(t *testing.T) {
	recorder := &translateRecorder{}
	module := newTranslatingVendor(recorder)
	lease := &sessionLease{pool: translatingPool(t, module), handle: 1}

	err := lease.DoRaw(context.Background(), func(raw.Module, raw.SessionHandle) error {
		return raw.Error(testVendorErrUnreachable)
	})
	if !raw.IsError(err, raw.CKR_DEVICE_ERROR) {
		t.Fatalf("DoRaw error = %v, want translated CKR_DEVICE_ERROR", err)
	}
	if len(recorder.seen) != 1 || !raw.IsError(recorder.seen[0], raw.CKR_DEVICE_ERROR) || recorder.actions[0] != RecoveryReinitialize {
		t.Fatalf("classifier observations = %v/%v, want translated error + RecoveryReinitialize",
			recorder.seen, recorder.actions)
	}
	if !lease.broken.Load() {
		t.Fatal("reinitialize-classified error must mark the session broken")
	}
}

func TestClientCallTranslatesModuleLevelErrors(t *testing.T) {
	recorder := &translateRecorder{}
	module := newTranslatingVendor(recorder)
	device := deviceForVendor(t, module, nil)
	client := &Client{module: &moduleRef{raw: testmock.New("translate", 1)}, device: device}

	err := client.call(context.Background(), "C_GetInfo", func(raw.Module) error {
		return raw.Error(testVendorErrUnreachable)
	})
	if !raw.IsError(err, raw.CKR_DEVICE_ERROR) {
		t.Fatalf("client.call error = %v, want translated CKR_DEVICE_ERROR", err)
	}
	// Client.call defers classification to its callers; the value they receive
	// must already be the standard result.
	if got := classifyDeviceError(device, err, false); got != RecoveryReinitialize {
		t.Fatalf("downstream classification = %v, want RecoveryReinitialize", got)
	}
}

func TestManagedBoundariesLeaveUnmappedVendorErrorsUntouched(t *testing.T) {
	module := newTranslatingVendor(&translateRecorder{})
	lease := &sessionLease{pool: translatingPool(t, module), handle: 1}
	unmapped := raw.Error(uint(0x80005017))
	err := lease.DoRaw(context.Background(), func(raw.Module, raw.SessionHandle) error {
		return unmapped
	})
	if err == nil || !raw.IsError(err, 0x80005017) {
		t.Fatalf("unmapped vendor error = %v, want unchanged 0x80005017", err)
	}
	if lease.broken.Load() {
		t.Fatal("terminal vendor error must not mark the session broken")
	}
}
