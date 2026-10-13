package conformance

import (
	"context"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// testSession is a conformance-only convenience wrapper around the public raw
// escape hatch. It deliberately does not live in the root driver API: normal
// applications should use Client operations, while conformance tests sometimes
// need exact Cryptoki calls and handles to validate low-level behavior.
type testSession struct {
	module raw.Module
	handle raw.SessionHandle
}

// cancelAllOperationFlags selects every operation class for C_SessionCancel.
const cancelAllOperationFlags = raw.CKF_FIND_OBJECTS | raw.CKF_MESSAGE_ENCRYPT |
	raw.CKF_MESSAGE_DECRYPT | raw.CKF_MESSAGE_SIGN | raw.CKF_MESSAGE_VERIFY |
	raw.CKF_ENCRYPT | raw.CKF_DECRYPT | raw.CKF_DIGEST | raw.CKF_SIGN |
	raw.CKF_SIGN_RECOVER | raw.CKF_VERIFY | raw.CKF_VERIFY_RECOVER

func (r *Runner) withSessionOptions(ctx context.Context, options pkcs11.RawSessionOptions, fn func(*testSession) error) error {
	return r.client.WithRawSession(ctx, options, func(module raw.Module, handle raw.SessionHandle) error {
		// Cases that intentionally fail operations can leave the token's
		// operation state active; cancel it before the session returns to the
		// pool so a later case does not inherit a poisoned slot. Providers
		// without C_SessionCancel return an error that is safe to ignore.
		defer func() { _ = module.SessionCancel(handle, cancelAllOperationFlags) }()
		return fn(&testSession{module: module, handle: handle})
	})
}

func (r *Runner) withReadOnlySession(ctx context.Context, fn func(*testSession) error) error {
	return r.withSessionOptions(ctx, pkcs11.RawSessionOptions{
		Operation:  "conformance-read-only-session",
		Idempotent: true,
	}, fn)
}

func (r *Runner) withReadWriteSession(ctx context.Context, fn func(*testSession) error) error {
	return r.withSessionOptions(ctx, pkcs11.RawSessionOptions{
		Operation: "conformance-read-write-session",
		ReadWrite: true,
	}, fn)
}

func (s *testSession) GetSessionInfo() (raw.SessionInfo, error) {
	return s.module.GetSessionInfo(s.handle)
}

func (s *testSession) CreateObject(attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	return s.module.CreateObject(s.handle, attributes)
}

func (s *testSession) CopyObject(object raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	return s.module.CopyObject(s.handle, object, attributes)
}

func (s *testSession) DestroyObject(object raw.ObjectHandle) error {
	return s.module.DestroyObject(s.handle, object)
}

func (s *testSession) GetAttributeValue(object raw.ObjectHandle, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	return s.module.GetAttributeValue(s.handle, object, attributes)
}

func (s *testSession) FindAllObjects(attributes []*raw.Attribute, batchSize int) ([]raw.ObjectHandle, error) {
	return s.module.FindAllObjects(s.handle, attributes, batchSize)
}

func (s *testSession) GenerateKey(mechanisms []*raw.Mechanism, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	return s.module.GenerateKey(s.handle, mechanisms, attributes)
}

func (s *testSession) GenerateKeyPair(mechanisms []*raw.Mechanism, publicAttributes, privateAttributes []*raw.Attribute) (raw.ObjectHandle, raw.ObjectHandle, error) {
	return s.module.GenerateKeyPair(s.handle, mechanisms, publicAttributes, privateAttributes)
}

func (s *testSession) DigestInit(mechanisms []*raw.Mechanism) error {
	return s.module.DigestInit(s.handle, mechanisms)
}

func (s *testSession) Digest(data []byte) ([]byte, error) {
	return s.module.Digest(s.handle, data)
}

func (s *testSession) EncryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.EncryptInit(s.handle, mechanisms, key)
}

func (s *testSession) Encrypt(data []byte) ([]byte, error) {
	return s.module.Encrypt(s.handle, data)
}

func (s *testSession) DecryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.DecryptInit(s.handle, mechanisms, key)
}

func (s *testSession) Decrypt(data []byte) ([]byte, error) {
	return s.module.Decrypt(s.handle, data)
}

func (s *testSession) SignInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.SignInit(s.handle, mechanisms, key)
}

func (s *testSession) Sign(data []byte) ([]byte, error) {
	return s.module.Sign(s.handle, data)
}

func (s *testSession) VerifyInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.VerifyInit(s.handle, mechanisms, key)
}

func (s *testSession) Verify(data, signature []byte) error {
	return s.module.Verify(s.handle, data, signature)
}

func (s *testSession) SignFinal() ([]byte, error) {
	return s.module.SignFinal(s.handle)
}

func (s *testSession) VerifyFinal(signature []byte) error {
	return s.module.VerifyFinal(s.handle, signature)
}

func (s *testSession) DeriveKey(mechanisms []*raw.Mechanism, baseKey raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	return s.module.DeriveKey(s.handle, mechanisms, baseKey, attributes)
}

func (s *testSession) WrapKey(mechanisms []*raw.Mechanism, wrappingKey, key raw.ObjectHandle) ([]byte, error) {
	return s.module.WrapKey(s.handle, mechanisms, wrappingKey, key)
}

func (s *testSession) UnwrapKey(mechanisms []*raw.Mechanism, unwrappingKey raw.ObjectHandle, wrapped []byte, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	return s.module.UnwrapKey(s.handle, mechanisms, unwrappingKey, wrapped, attributes)
}

func (s *testSession) MessageSignInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.MessageSignInit(s.handle, mechanisms, key)
}

func (s *testSession) SignMessage(parameter any, data []byte) ([]byte, error) {
	return s.module.SignMessage(s.handle, parameter, data)
}

func (s *testSession) MessageEncryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.MessageEncryptInit(s.handle, mechanisms, key)
}

func (s *testSession) EncryptMessage(parameter any, associatedData, plaintext []byte) ([]byte, error) {
	return s.module.EncryptMessage(s.handle, parameter, associatedData, plaintext)
}

func (s *testSession) MessageEncryptFinal() error {
	return s.module.MessageEncryptFinal(s.handle)
}

func (s *testSession) MessageDecryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.MessageDecryptInit(s.handle, mechanisms, key)
}

func (s *testSession) DecryptMessage(parameter any, associatedData, ciphertext []byte) ([]byte, error) {
	return s.module.DecryptMessage(s.handle, parameter, associatedData, ciphertext)
}

func (s *testSession) MessageDecryptFinal() error {
	return s.module.MessageDecryptFinal(s.handle)
}

func (s *testSession) MessageVerifyInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	return s.module.MessageVerifyInit(s.handle, mechanisms, key)
}

func (s *testSession) VerifyMessage(parameter any, data, signature []byte) error {
	return s.module.VerifyMessage(s.handle, parameter, data, signature)
}

func (s *testSession) VerifySignatureInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle, signature []byte) error {
	return s.module.VerifySignatureInit(s.handle, mechanisms, key, signature)
}

func (s *testSession) VerifySignature(data []byte) error {
	return s.module.VerifySignature(s.handle, data)
}

func (s *testSession) GetSessionValidationFlags(typ raw.ValidationFlagsType) (raw.Flags, error) {
	return s.module.GetSessionValidationFlags(s.handle, typ)
}
