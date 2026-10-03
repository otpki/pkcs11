package testmock

import (
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// This file holds the raw.Module surface the fixture does not implement.
// Everything here reports CKR_FUNCTION_NOT_SUPPORTED (or the spec-mandated
// legacy response) so callers see the same failure they would get from a real
// module that lacks the function.

// InitToken reinitializes a slot: new label and PIN, all objects and sessions
// on the token destroyed.
func (m *Module) InitToken(slot raw.SlotID, pin []byte, label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, err := m.lookup(slot)
	if err != nil {
		return err
	}
	if len(pin) > 0 {
		t.pin = append(t.pin[:0], pin...)
	}
	if strings.TrimSpace(label) != "" {
		t.label = label
	}
	t.loggedIn = false
	for h, s := range m.sessions {
		if s.slot == slot {
			delete(m.sessions, h)
		}
	}
	t.objects = make(map[raw.ObjectHandle]*object)
	t.nextObj = 1
	return nil
}

// InitPIN sets the user PIN. Real modules gate this on an SO session; the
// fixture has no SO role so it simply applies the value.
func (m *Module) InitPIN(handle raw.SessionHandle, pin []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if len(pin) < 1 || len(pin) > 64 {
		return raw.Error(raw.CKR_PIN_LEN_RANGE)
	}
	t.pin = append(t.pin[:0], pin...)
	return nil
}

// GetFunctionStatus is a deprecated legacy entry point; the spec response for a
// module without parallel functions is CKR_FUNCTION_NOT_PARALLEL.
func (m *Module) GetFunctionStatus(_ raw.SessionHandle) error {
	return raw.Error(raw.CKR_FUNCTION_NOT_PARALLEL)
}

// CancelFunction reports no running parallel function.
func (m *Module) CancelFunction(_ raw.SessionHandle) error {
	return raw.Error(raw.CKR_FUNCTION_NOT_PARALLEL)
}

func (m *Module) GetOperationState(raw.SessionHandle) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) SetOperationState(raw.SessionHandle, []byte, raw.ObjectHandle, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) EncryptUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) EncryptFinal(raw.SessionHandle) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DecryptUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DecryptFinal(raw.SessionHandle) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DigestKey(raw.SessionHandle, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) SignUpdate(raw.SessionHandle, []byte) error {
	return errUnsupported
}

func (m *Module) SignFinal(raw.SessionHandle) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) SignRecoverInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) SignRecover(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) VerifyUpdate(raw.SessionHandle, []byte) error {
	return errUnsupported
}

func (m *Module) VerifyFinal(raw.SessionHandle, []byte) error {
	return errUnsupported
}

func (m *Module) VerifyRecoverInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) VerifyRecover(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DigestEncryptUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DecryptDigestUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) SignEncryptUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DecryptVerifyUpdate(raw.SessionHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) WrapKey(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, raw.ObjectHandle) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) UnwrapKey(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []byte, []*raw.Attribute) (raw.ObjectHandle, error) {
	return 0, errUnsupported
}

func (m *Module) DeriveKey(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []*raw.Attribute) (raw.ObjectHandle, error) {
	return 0, errUnsupported
}

func (m *Module) WrapKeyAuthenticated(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, raw.ObjectHandle, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) UnwrapKeyAuthenticated(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []byte, []*raw.Attribute, []byte) (raw.ObjectHandle, error) {
	return 0, errUnsupported
}

func (m *Module) EncapsulateKey(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []*raw.Attribute) ([]byte, raw.ObjectHandle, error) {
	return nil, 0, errUnsupported
}

func (m *Module) DecapsulateKey(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []byte, []*raw.Attribute) (raw.ObjectHandle, error) {
	return 0, errUnsupported
}

func (m *Module) VerifySignatureInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle, []byte) error {
	return errUnsupported
}

func (m *Module) VerifySignature(raw.SessionHandle, []byte) error {
	return errUnsupported
}

func (m *Module) VerifySignatureUpdate(raw.SessionHandle, []byte) error {
	return errUnsupported
}

func (m *Module) VerifySignatureFinal(raw.SessionHandle) error {
	return errUnsupported
}

func (m *Module) GetSessionValidationFlags(raw.SessionHandle, raw.ValidationFlagsType) (raw.Flags, error) {
	return 0, errUnsupported
}

func (m *Module) AsyncComplete(raw.SessionHandle, string, *raw.AsyncData) error {
	return errUnsupported
}

func (m *Module) AsyncGetID(raw.SessionHandle, string) (uint, error) {
	return 0, errUnsupported
}

func (m *Module) AsyncJoin(raw.SessionHandle, string, uint, []byte) error {
	return errUnsupported
}

func (m *Module) MessageEncryptInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) EncryptMessage(raw.SessionHandle, any, []byte, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) EncryptMessageBegin(raw.SessionHandle, any, []byte) error {
	return errUnsupported
}

func (m *Module) EncryptMessageNext(raw.SessionHandle, any, []byte, uint) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) MessageEncryptFinal(raw.SessionHandle) error {
	return errUnsupported
}

func (m *Module) MessageDecryptInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) DecryptMessage(raw.SessionHandle, any, []byte, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) DecryptMessageBegin(raw.SessionHandle, any, []byte) error {
	return errUnsupported
}

func (m *Module) DecryptMessageNext(raw.SessionHandle, any, []byte, uint) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) MessageDecryptFinal(raw.SessionHandle) error {
	return errUnsupported
}

func (m *Module) MessageSignInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) SignMessage(raw.SessionHandle, any, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) SignMessageBegin(raw.SessionHandle, any) error {
	return errUnsupported
}

func (m *Module) SignMessageNext(raw.SessionHandle, any, []byte) ([]byte, error) {
	return nil, errUnsupported
}

func (m *Module) MessageSignFinal(raw.SessionHandle) error {
	return errUnsupported
}

func (m *Module) MessageVerifyInit(raw.SessionHandle, []*raw.Mechanism, raw.ObjectHandle) error {
	return errUnsupported
}

func (m *Module) VerifyMessage(raw.SessionHandle, any, []byte, []byte) error {
	return errUnsupported
}

func (m *Module) VerifyMessageBegin(raw.SessionHandle, any) error {
	return errUnsupported
}

func (m *Module) VerifyMessageNext(raw.SessionHandle, any, []byte, []byte) error {
	return errUnsupported
}

func (m *Module) MessageVerifyFinal(raw.SessionHandle) error {
	return errUnsupported
}
