package pkcs11

import (
	"context"
	"errors"
	"fmt"

	"github.com/otpki/pkcs11/raw"
)

// call is the common execution boundary for session-bound operations. It checks
// lease state, emits hooks, preserves serialization/thread affinity, and marks
// the handle broken when recovery classification says it cannot be reused.
func (s *sessionLease) call(operation string, fn func(raw.Module) error) error {
	return s.callContext(s.Context(), operation, fn)
}

func (s *sessionLease) callContext(ctx context.Context, operation string, fn func(raw.Module) error) (err error) {
	if s == nil || s.pool == nil || s.pool.module == nil || s.closed.Load() {
		return errors.New("pkcs11: session is closed")
	}
	if ctx == nil {
		ctx = s.Context()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	device := s.pool.currentDevice()
	event := OperationEvent{
		Operation:  operation,
		ModulePath: s.pool.module.path,
		Vendor:     device.Adapter.Name,
		SlotID:     device.Fingerprint.SlotID,
		Session:    s.handle,
		ReadWrite:  s.ReadWrite(),
		Attempt:    s.attempt,
	}
	// Hooks receive the possibly enriched context and exactly one completion call,
	// including when the enriched context is already canceled.
	ctx, finish := s.pool.hooks.begin(ctx, event)
	defer func() { finish(err) }()
	if err = ctx.Err(); err != nil {
		return err
	}
	s.uses.Add(1)
	err = s.pool.execute(ctx, s.worker, fn)
	// Any error that triggers managed recovery also makes this concrete session
	// unsafe to return to the pool, even if the high-level caller will not retry.
	if classifyDeviceError(device, err, false) != RecoveryNone {
		s.MarkBroken()
	}
	return err
}

// sessionValue adapts a value-returning raw call to the session call boundary
// without duplicating hook and recovery logic.
func sessionValue[T any](s *sessionLease, operation string, fn func(raw.Module) (T, error)) (value T, err error) {
	err = s.call(operation, func(module raw.Module) error {
		value, err = fn(module)
		return err
	})
	return value, err
}

// call is the common execution boundary for module-level operations. It applies
// hooks and adapter serialization but does not acquire a token session.
func (c *Client) call(ctx context.Context, operation string, fn func(raw.Module) error) (err error) {
	if c == nil || c.module == nil || c.closed.Load() {
		return errors.New("pkcs11: client is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	device := c.currentDevice()
	event := OperationEvent{
		Operation:  operation,
		ModulePath: c.module.path,
		Vendor:     device.Adapter.Name,
		SlotID:     device.Fingerprint.SlotID,
	}
	ctx, finish := c.hooks.begin(ctx, event)
	defer func() { finish(err) }()
	if err = ctx.Err(); err != nil {
		return err
	}
	return c.module.execute(ctx, device.plan, fn)
}

// clientValue adapts a value-returning module call to Client.call.
func clientValue[T any](ctx context.Context, c *Client, operation string, fn func(raw.Module) (T, error)) (value T, err error) {
	err = c.call(ctx, operation, func(module raw.Module) error {
		value, err = fn(module)
		return err
	})
	return value, err
}

// Module and slot operations.

// getInfo returns module metadata through the managed module call boundary.
func (c *Client) getInfo(ctx context.Context) (raw.Info, error) {
	return clientValue(ctx, c, "C_GetInfo", func(module raw.Module) (raw.Info, error) { return module.GetInfo() })
}

// getInterfaceList enumerates interfaces advertised by the loaded module.
func (c *Client) getInterfaceList(ctx context.Context) ([]raw.InterfaceInfo, error) {
	return clientValue(ctx, c, "C_GetInterfaceList", func(module raw.Module) ([]raw.InterfaceInfo, error) { return module.GetInterfaceList() })
}

// getSlotList enumerates slots, optionally restricting results to present tokens.
func (c *Client) getSlotList(ctx context.Context, tokenPresent bool) ([]raw.SlotID, error) {
	return clientValue(ctx, c, "C_GetSlotList", func(module raw.Module) ([]raw.SlotID, error) { return module.GetSlotList(tokenPresent) })
}

// getSlotInfo returns metadata for one slot.
func (c *Client) getSlotInfo(ctx context.Context, slot raw.SlotID) (raw.SlotInfo, error) {
	return clientValue(ctx, c, "C_GetSlotInfo", func(module raw.Module) (raw.SlotInfo, error) { return module.GetSlotInfo(slot) })
}

// getTokenInfo returns token metadata for one slot.
func (c *Client) getTokenInfo(ctx context.Context, slot raw.SlotID) (raw.TokenInfo, error) {
	return clientValue(ctx, c, "C_GetTokenInfo", func(module raw.Module) (raw.TokenInfo, error) { return module.GetTokenInfo(slot) })
}

// getMechanismList returns the mechanisms advertised by one token.
func (c *Client) getMechanismList(ctx context.Context, slot raw.SlotID) ([]raw.MechanismType, error) {
	return clientValue(ctx, c, "C_GetMechanismList", func(module raw.Module) ([]raw.MechanismType, error) { return module.GetMechanismList(slot) })
}

// getMechanismInfo returns limits and capability flags for one mechanism.
func (c *Client) getMechanismInfo(ctx context.Context, slot raw.SlotID, mechanism raw.MechanismType) (raw.MechanismInfo, error) {
	return clientValue(ctx, c, "C_GetMechanismInfo", func(module raw.Module) (raw.MechanismInfo, error) {
		return module.GetMechanismInfo(slot, mechanism)
	})
}

// initToken initializes or reinitializes a token and invalidates every cached
// session, object lookup, attribute value, and remembered login observation.
func (c *Client) initToken(ctx context.Context, slot raw.SlotID, pin Secret, label string) error {
	err := c.call(ctx, "C_InitToken", func(module raw.Module) error { return module.InitToken(slot, pin, label) })
	if err == nil {
		// Token initialization can replace every object, credential, and session
		// assumption held by the client.
		c.invalidateState()
	}
	return err
}

// waitForSlotEvent calls the native blocking API. Context is checked before
// entering the vendor module; PKCS #11 provides no portable cancellation hook
// for an already-blocked C_WaitForSlotEvent call.
func (c *Client) waitForSlotEvent(ctx context.Context, flags uint) (raw.SlotID, error) {
	return clientValue(ctx, c, "C_WaitForSlotEvent", func(module raw.Module) (raw.SlotID, error) {
		return module.WaitForSlotEvent(flags)
	})
}

// sessionLease and credential operations.

// InitPIN initializes the normal user's PIN through C_InitPIN.
func (s *sessionLease) InitPIN(pin Secret) error {
	return s.call("C_InitPIN", func(module raw.Module) error { return module.InitPIN(s.handle, pin) })
}

// SetPIN changes the PIN for the identity authenticated on this session.
func (s *sessionLease) SetPIN(oldPIN, newPIN Secret) error {
	return s.call("C_SetPIN", func(module raw.Module) error { return module.SetPIN(s.handle, oldPIN, newPIN) })
}

// GetSessionInfo returns the current native session state and flags.
func (s *sessionLease) GetSessionInfo() (raw.SessionInfo, error) {
	return sessionValue(s, "C_GetSessionInfo", func(module raw.Module) (raw.SessionInfo, error) {
		return module.GetSessionInfo(s.handle)
	})
}

// GetOperationState serializes the token-managed state of active operations.
func (s *sessionLease) GetOperationState() ([]byte, error) {
	return sessionValue(s, "C_GetOperationState", func(module raw.Module) ([]byte, error) {
		return module.GetOperationState(s.handle)
	})
}

// SetOperationState restores previously serialized operation state and supplies
// any keys the token requires to resume it.
func (s *sessionLease) SetOperationState(state []byte, encryptionKey, authenticationKey raw.ObjectHandle) error {
	return s.call("C_SetOperationState", func(module raw.Module) error {
		return module.SetOperationState(s.handle, state, encryptionKey, authenticationKey)
	})
}

// Login performs a direct C_Login on this session. High-level code normally uses
// the pool login coordinator instead.
func (s *sessionLease) Login(userType uint, pin Secret) error {
	return s.call("C_Login", func(module raw.Module) error { return module.Login(s.handle, userType, pin) })
}

// LoginUser performs PKCS #11 3.x username-aware authentication on this session.
func (s *sessionLease) LoginUser(userType uint, pin Secret, username string) error {
	return s.call("C_LoginUser", func(module raw.Module) error { return module.LoginUser(s.handle, userType, pin, username) })
}

// ContextLogin performs C_Login with CKU_CONTEXT_SPECIFIC using the configured
// PIN provider and is suitable for CKA_ALWAYS_AUTHENTICATE keys.
func (s *sessionLease) ContextLogin() error {
	if s == nil || s.pool == nil {
		return errors.New("pkcs11: session is closed")
	}
	return s.pool.ContextLogin(s.Context(), s.handle, s.worker)
}

// Logout terminates the token/application login state associated with the session.
func (s *sessionLease) Logout() error {
	return s.call("C_Logout", func(module raw.Module) error { return module.Logout(s.handle) })
}

// SessionCancel requests cancellation of active operation classes selected by flags.
func (s *sessionLease) SessionCancel(flags uint) error {
	return s.call("C_SessionCancel", func(module raw.Module) error { return module.SessionCancel(s.handle, flags) })
}

// GetFunctionStatus reports status for legacy parallel-function execution.
func (s *sessionLease) GetFunctionStatus() error {
	return s.call("C_GetFunctionStatus", func(module raw.Module) error { return module.GetFunctionStatus(s.handle) })
}

// CancelFunction requests cancellation of a legacy parallel function.
func (s *sessionLease) CancelFunction() error {
	return s.call("C_CancelFunction", func(module raw.Module) error { return module.CancelFunction(s.handle) })
}

// Object operations.

// CreateObject creates a token or session object after applying vendor template
// normalization, then invalidates object and attribute caches.
func (s *sessionLease) CreateObject(attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	device := s.currentDevice()
	adapted, err := normalizeVendorTemplate(device, "C_CreateObject", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_CreateObject", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.CreateObject(s.handle, adapted)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// CopyObject duplicates an object with normalized override attributes and
// invalidates caches after successful creation.
func (s *sessionLease) CopyObject(object raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	device := s.currentDevice()
	adapted, err := normalizeVendorTemplate(device, "C_CopyObject", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_CopyObject", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.CopyObject(s.handle, object, adapted)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// DestroyObject removes an object and invalidates all token caches on success.
func (s *sessionLease) DestroyObject(object raw.ObjectHandle) error {
	err := s.call("C_DestroyObject", func(module raw.Module) error { return module.DestroyObject(s.handle, object) })
	if err == nil {
		s.invalidateCache()
	}
	return err
}

// GetObjectSize returns the token-reported storage size of an object.
func (s *sessionLease) GetObjectSize(object raw.ObjectHandle) (uint, error) {
	return sessionValue(s, "C_GetObjectSize", func(module raw.Module) (uint, error) {
		return module.GetObjectSize(s.handle, object)
	})
}

// GetAttributeValue reads the requested attribute template from an object.
func (s *sessionLease) GetAttributeValue(object raw.ObjectHandle, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	return sessionValue(s, "C_GetAttributeValue", func(module raw.Module) ([]*raw.Attribute, error) {
		return module.GetAttributeValue(s.handle, object, attributes)
	})
}

// SetAttributeValue applies normalized mutable attributes and invalidates caches
// after a successful update.
func (s *sessionLease) SetAttributeValue(object raw.ObjectHandle, attributes []*raw.Attribute) error {
	adapted, err := normalizeVendorTemplate(s.currentDevice(), "C_SetAttributeValue", attributes)
	if err != nil {
		return err
	}
	err = s.call("C_SetAttributeValue", func(module raw.Module) error {
		return module.SetAttributeValue(s.handle, object, adapted)
	})
	if err == nil {
		s.invalidateCache()
	}
	return err
}

// FindObjectsInit starts a stateful object search on this session.
func (s *sessionLease) FindObjectsInit(attributes []*raw.Attribute) error {
	return s.call("C_FindObjectsInit", func(module raw.Module) error {
		return module.FindObjectsInit(s.handle, attributes)
	})
}

// FindObjects returns the next search batch and whether more objects may remain.
func (s *sessionLease) FindObjects(max int) ([]raw.ObjectHandle, bool, error) {
	type result struct {
		objects []raw.ObjectHandle
		more    bool
	}
	value, err := sessionValue(s, "C_FindObjects", func(module raw.Module) (result, error) {
		objects, more, callErr := module.FindObjects(s.handle, max)
		return result{objects: objects, more: more}, callErr
	})
	return value.objects, value.more, err
}

// FindObjectsFinal releases token state associated with the current object search.
func (s *sessionLease) FindObjectsFinal() error {
	return s.call("C_FindObjectsFinal", func(module raw.Module) error { return module.FindObjectsFinal(s.handle) })
}

// FindAllObjects performs the complete init/iterate/final search sequence.
func (s *sessionLease) FindAllObjects(attributes []*raw.Attribute, batchSize int) ([]raw.ObjectHandle, error) {
	return sessionValue(s, "C_FindObjects", func(module raw.Module) ([]raw.ObjectHandle, error) {
		return module.FindAllObjects(s.handle, attributes, batchSize)
	})
}

// Conventional cryptographic operations.

// EncryptInit initializes conventional encryption with normalized mechanisms.
func (s *sessionLease) EncryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	device := s.currentDevice()
	adapted, err := normalizeVendorMechanisms(device, "C_EncryptInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_EncryptInit", func(module raw.Module) error { return module.EncryptInit(s.handle, adapted, key) })
}

// Encrypt performs a single-part encryption operation.
func (s *sessionLease) Encrypt(plaintext []byte) ([]byte, error) {
	return sessionValue(s, "C_Encrypt", func(module raw.Module) ([]byte, error) { return module.Encrypt(s.handle, plaintext) })
}

// EncryptUpdate processes the next plaintext part of a multipart operation.
func (s *sessionLease) EncryptUpdate(plaintext []byte) ([]byte, error) {
	return sessionValue(s, "C_EncryptUpdate", func(module raw.Module) ([]byte, error) { return module.EncryptUpdate(s.handle, plaintext) })
}

// EncryptFinal completes multipart encryption and returns any final output.
func (s *sessionLease) EncryptFinal() ([]byte, error) {
	return sessionValue(s, "C_EncryptFinal", func(module raw.Module) ([]byte, error) { return module.EncryptFinal(s.handle) })
}

// DecryptInit initializes conventional decryption with normalized mechanisms.
func (s *sessionLease) DecryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	device := s.currentDevice()
	adapted, err := normalizeVendorMechanisms(device, "C_DecryptInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_DecryptInit", func(module raw.Module) error { return module.DecryptInit(s.handle, adapted, key) })
}

// Decrypt performs a single-part decryption operation.
func (s *sessionLease) Decrypt(ciphertext []byte) ([]byte, error) {
	return sessionValue(s, "C_Decrypt", func(module raw.Module) ([]byte, error) { return module.Decrypt(s.handle, ciphertext) })
}

// DecryptUpdate processes the next ciphertext part of a multipart operation.
func (s *sessionLease) DecryptUpdate(ciphertext []byte) ([]byte, error) {
	return sessionValue(s, "C_DecryptUpdate", func(module raw.Module) ([]byte, error) { return module.DecryptUpdate(s.handle, ciphertext) })
}

// DecryptFinal completes multipart decryption and returns any final plaintext.
func (s *sessionLease) DecryptFinal() ([]byte, error) {
	return sessionValue(s, "C_DecryptFinal", func(module raw.Module) ([]byte, error) { return module.DecryptFinal(s.handle) })
}

// DigestInit initializes a message-digest operation.
func (s *sessionLease) DigestInit(mechanisms []*raw.Mechanism) error {
	return s.call("C_DigestInit", func(module raw.Module) error { return module.DigestInit(s.handle, mechanisms) })
}

// Digest computes a digest in one call.
func (s *sessionLease) Digest(data []byte) ([]byte, error) {
	return sessionValue(s, "C_Digest", func(module raw.Module) ([]byte, error) { return module.Digest(s.handle, data) })
}

// DigestUpdate supplies another part to an active digest operation.
func (s *sessionLease) DigestUpdate(data []byte) error {
	return s.call("C_DigestUpdate", func(module raw.Module) error { return module.DigestUpdate(s.handle, data) })
}

// DigestKey incorporates a secret key value without exporting it from the token.
func (s *sessionLease) DigestKey(key raw.ObjectHandle) error {
	return s.call("C_DigestKey", func(module raw.Module) error { return module.DigestKey(s.handle, key) })
}

// DigestFinal completes a multipart digest operation.
func (s *sessionLease) DigestFinal() ([]byte, error) {
	return sessionValue(s, "C_DigestFinal", func(module raw.Module) ([]byte, error) { return module.DigestFinal(s.handle) })
}

// SignInit initializes conventional signing with normalized mechanisms.
func (s *sessionLease) SignInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	device := s.currentDevice()
	adapted, err := normalizeVendorMechanisms(device, "C_SignInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_SignInit", func(module raw.Module) error { return module.SignInit(s.handle, adapted, key) })
}

// Sign produces a signature or MAC in one call.
func (s *sessionLease) Sign(data []byte) ([]byte, error) {
	return sessionValue(s, "C_Sign", func(module raw.Module) ([]byte, error) { return module.Sign(s.handle, data) })
}

// SignUpdate supplies another part to a multipart signing operation.
func (s *sessionLease) SignUpdate(data []byte) error {
	return s.call("C_SignUpdate", func(module raw.Module) error { return module.SignUpdate(s.handle, data) })
}

// SignFinal completes multipart signing and returns the signature.
func (s *sessionLease) SignFinal() ([]byte, error) {
	return sessionValue(s, "C_SignFinal", func(module raw.Module) ([]byte, error) { return module.SignFinal(s.handle) })
}

// SignRecoverInit initializes a signature-with-recovery operation.
func (s *sessionLease) SignRecoverInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_SignRecoverInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_SignRecoverInit", func(module raw.Module) error { return module.SignRecoverInit(s.handle, adapted, key) })
}

// SignRecover creates a signature from which the signed data can be recovered.
func (s *sessionLease) SignRecover(data []byte) ([]byte, error) {
	return sessionValue(s, "C_SignRecover", func(module raw.Module) ([]byte, error) { return module.SignRecover(s.handle, data) })
}

// VerifyInit initializes conventional verification with normalized mechanisms.
func (s *sessionLease) VerifyInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	device := s.currentDevice()
	adapted, err := normalizeVendorMechanisms(device, "C_VerifyInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_VerifyInit", func(module raw.Module) error { return module.VerifyInit(s.handle, adapted, key) })
}

// Verify checks a single-part signature or MAC.
func (s *sessionLease) Verify(data, signature []byte) error {
	return s.call("C_Verify", func(module raw.Module) error { return module.Verify(s.handle, data, signature) })
}

// VerifyUpdate supplies another part to a multipart verification operation.
func (s *sessionLease) VerifyUpdate(data []byte) error {
	return s.call("C_VerifyUpdate", func(module raw.Module) error { return module.VerifyUpdate(s.handle, data) })
}

// VerifyFinal completes multipart verification against signature.
func (s *sessionLease) VerifyFinal(signature []byte) error {
	return s.call("C_VerifyFinal", func(module raw.Module) error { return module.VerifyFinal(s.handle, signature) })
}

// VerifyRecoverInit initializes verification with message recovery.
func (s *sessionLease) VerifyRecoverInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_VerifyRecoverInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_VerifyRecoverInit", func(module raw.Module) error { return module.VerifyRecoverInit(s.handle, adapted, key) })
}

// VerifyRecover verifies a signature and returns the recovered signed data.
func (s *sessionLease) VerifyRecover(signature []byte) ([]byte, error) {
	return sessionValue(s, "C_VerifyRecover", func(module raw.Module) ([]byte, error) { return module.VerifyRecover(s.handle, signature) })
}

// DigestEncryptUpdate feeds data through active digest and encryption operations.
func (s *sessionLease) DigestEncryptUpdate(data []byte) ([]byte, error) {
	return sessionValue(s, "C_DigestEncryptUpdate", func(module raw.Module) ([]byte, error) { return module.DigestEncryptUpdate(s.handle, data) })
}

// DecryptDigestUpdate feeds data through active decryption and digest operations.
func (s *sessionLease) DecryptDigestUpdate(data []byte) ([]byte, error) {
	return sessionValue(s, "C_DecryptDigestUpdate", func(module raw.Module) ([]byte, error) { return module.DecryptDigestUpdate(s.handle, data) })
}

// SignEncryptUpdate feeds data through active signing and encryption operations.
func (s *sessionLease) SignEncryptUpdate(data []byte) ([]byte, error) {
	return sessionValue(s, "C_SignEncryptUpdate", func(module raw.Module) ([]byte, error) { return module.SignEncryptUpdate(s.handle, data) })
}

// DecryptVerifyUpdate feeds data through active decryption and verification operations.
func (s *sessionLease) DecryptVerifyUpdate(data []byte) ([]byte, error) {
	return sessionValue(s, "C_DecryptVerifyUpdate", func(module raw.Module) ([]byte, error) { return module.DecryptVerifyUpdate(s.handle, data) })
}

// Key management and random operations.

// GenerateKey creates a secret key using normalized mechanisms and attributes,
// then invalidates token caches.
func (s *sessionLease) GenerateKey(mechanisms []*raw.Mechanism, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	device := s.currentDevice()
	adaptedMechanisms, err := normalizeVendorMechanisms(device, "C_GenerateKey", mechanisms)
	if err != nil {
		return 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(device, "C_GenerateKey", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_GenerateKey", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.GenerateKey(s.handle, adaptedMechanisms, adaptedAttributes)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// GenerateKeyPair creates public and private key objects using independently
// normalized templates, then invalidates token caches.
func (s *sessionLease) GenerateKeyPair(mechanisms []*raw.Mechanism, publicAttributes, privateAttributes []*raw.Attribute) (raw.ObjectHandle, raw.ObjectHandle, error) {
	device := s.currentDevice()
	adaptedMechanisms, err := normalizeVendorMechanisms(device, "C_GenerateKeyPair", mechanisms)
	if err != nil {
		return 0, 0, err
	}
	publicAttributes, err = normalizeVendorTemplate(device, "C_GenerateKeyPair/public", publicAttributes)
	if err != nil {
		return 0, 0, err
	}
	privateAttributes, err = normalizeVendorTemplate(device, "C_GenerateKeyPair/private", privateAttributes)
	if err != nil {
		return 0, 0, err
	}
	type pair struct{ public, private raw.ObjectHandle }
	value, err := sessionValue(s, "C_GenerateKeyPair", func(module raw.Module) (pair, error) {
		public, private, callErr := module.GenerateKeyPair(s.handle, adaptedMechanisms, publicAttributes, privateAttributes)
		return pair{public: public, private: private}, callErr
	})
	if err == nil {
		s.invalidateCache()
	}
	return value.public, value.private, err
}

// WrapKey exports key in wrapped form using normalized mechanisms.
func (s *sessionLease) WrapKey(mechanisms []*raw.Mechanism, wrappingKey, key raw.ObjectHandle) ([]byte, error) {
	device := s.currentDevice()
	adapted, err := normalizeVendorMechanisms(device, "C_WrapKey", mechanisms)
	if err != nil {
		return nil, err
	}
	return sessionValue(s, "C_WrapKey", func(module raw.Module) ([]byte, error) { return module.WrapKey(s.handle, adapted, wrappingKey, key) })
}

// UnwrapKey imports wrapped key material into a normalized object template and
// invalidates caches after successful creation.
func (s *sessionLease) UnwrapKey(mechanisms []*raw.Mechanism, unwrappingKey raw.ObjectHandle, wrapped []byte, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	device := s.currentDevice()
	adaptedMechanisms, err := normalizeVendorMechanisms(device, "C_UnwrapKey", mechanisms)
	if err != nil {
		return 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(device, "C_UnwrapKey", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_UnwrapKey", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.UnwrapKey(s.handle, adaptedMechanisms, unwrappingKey, wrapped, adaptedAttributes)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// DeriveKey creates a new key from baseKey using normalized mechanisms and
// attributes, then invalidates token caches.
func (s *sessionLease) DeriveKey(mechanisms []*raw.Mechanism, baseKey raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	device := s.currentDevice()
	adaptedMechanisms, err := normalizeVendorMechanisms(device, "C_DeriveKey", mechanisms)
	if err != nil {
		return 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(device, "C_DeriveKey", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_DeriveKey", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.DeriveKey(s.handle, adaptedMechanisms, baseKey, adaptedAttributes)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// SeedRandom contributes caller-provided seed material to the token RNG.
func (s *sessionLease) SeedRandom(seed []byte) error {
	return s.call("C_SeedRandom", func(module raw.Module) error { return module.SeedRandom(s.handle, seed) })
}

// GenerateRandom returns length bytes generated by the token RNG.
func (s *sessionLease) GenerateRandom(length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("pkcs11: negative random length %d", length)
	}
	return sessionValue(s, "C_GenerateRandom", func(module raw.Module) ([]byte, error) {
		return module.GenerateRandom(s.handle, length)
	})
}

// PKCS #11 3.x message operations.

// MessageEncryptInit initializes the PKCS #11 3.x message-encryption interface.
func (s *sessionLease) MessageEncryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_MessageEncryptInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_MessageEncryptInit", func(module raw.Module) error { return module.MessageEncryptInit(s.handle, adapted, key) })
}

// EncryptMessage encrypts one complete message with optional per-message parameters and AAD.
func (s *sessionLease) EncryptMessage(parameter any, associatedData, plaintext []byte) ([]byte, error) {
	return sessionValue(s, "C_EncryptMessage", func(module raw.Module) ([]byte, error) {
		return module.EncryptMessage(s.handle, parameter, associatedData, plaintext)
	})
}

// EncryptMessageBegin starts multipart message encryption.
func (s *sessionLease) EncryptMessageBegin(parameter any, associatedData []byte) error {
	return s.call("C_EncryptMessageBegin", func(module raw.Module) error { return module.EncryptMessageBegin(s.handle, parameter, associatedData) })
}

// EncryptMessageNext processes the next message-encryption part.
func (s *sessionLease) EncryptMessageNext(parameter any, plaintext []byte, flags uint) ([]byte, error) {
	return sessionValue(s, "C_EncryptMessageNext", func(module raw.Module) ([]byte, error) {
		return module.EncryptMessageNext(s.handle, parameter, plaintext, flags)
	})
}

// MessageEncryptFinal releases state for the active message-encryption operation.
func (s *sessionLease) MessageEncryptFinal() error {
	return s.call("C_MessageEncryptFinal", func(module raw.Module) error { return module.MessageEncryptFinal(s.handle) })
}

// MessageDecryptInit initializes the PKCS #11 3.x message-decryption interface.
func (s *sessionLease) MessageDecryptInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_MessageDecryptInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_MessageDecryptInit", func(module raw.Module) error { return module.MessageDecryptInit(s.handle, adapted, key) })
}

// DecryptMessage decrypts one complete message with optional per-message parameters and AAD.
func (s *sessionLease) DecryptMessage(parameter any, associatedData, ciphertext []byte) ([]byte, error) {
	return sessionValue(s, "C_DecryptMessage", func(module raw.Module) ([]byte, error) {
		return module.DecryptMessage(s.handle, parameter, associatedData, ciphertext)
	})
}

// DecryptMessageBegin starts multipart message decryption.
func (s *sessionLease) DecryptMessageBegin(parameter any, associatedData []byte) error {
	return s.call("C_DecryptMessageBegin", func(module raw.Module) error { return module.DecryptMessageBegin(s.handle, parameter, associatedData) })
}

// DecryptMessageNext processes the next message-decryption part.
func (s *sessionLease) DecryptMessageNext(parameter any, ciphertext []byte, flags uint) ([]byte, error) {
	return sessionValue(s, "C_DecryptMessageNext", func(module raw.Module) ([]byte, error) {
		return module.DecryptMessageNext(s.handle, parameter, ciphertext, flags)
	})
}

// MessageDecryptFinal releases state for the active message-decryption operation.
func (s *sessionLease) MessageDecryptFinal() error {
	return s.call("C_MessageDecryptFinal", func(module raw.Module) error { return module.MessageDecryptFinal(s.handle) })
}

// MessageSignInit initializes the PKCS #11 3.x message-signing interface.
func (s *sessionLease) MessageSignInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_MessageSignInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_MessageSignInit", func(module raw.Module) error { return module.MessageSignInit(s.handle, adapted, key) })
}

// SignMessage signs one complete message with optional per-message parameters.
func (s *sessionLease) SignMessage(parameter any, data []byte) ([]byte, error) {
	return sessionValue(s, "C_SignMessage", func(module raw.Module) ([]byte, error) {
		return module.SignMessage(s.handle, parameter, data)
	})
}

// SignMessageBegin starts multipart message signing.
func (s *sessionLease) SignMessageBegin(parameter any) error {
	return s.call("C_SignMessageBegin", func(module raw.Module) error { return module.SignMessageBegin(s.handle, parameter) })
}

// SignMessageNext processes the next message-signing part and returns its output.
func (s *sessionLease) SignMessageNext(parameter any, data []byte) ([]byte, error) {
	return sessionValue(s, "C_SignMessageNext", func(module raw.Module) ([]byte, error) {
		return module.SignMessageNext(s.handle, parameter, data)
	})
}

// MessageSignFinal releases state for the active message-signing operation.
func (s *sessionLease) MessageSignFinal() error {
	return s.call("C_MessageSignFinal", func(module raw.Module) error { return module.MessageSignFinal(s.handle) })
}

// MessageVerifyInit initializes the PKCS #11 3.x message-verification interface.
func (s *sessionLease) MessageVerifyInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_MessageVerifyInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_MessageVerifyInit", func(module raw.Module) error { return module.MessageVerifyInit(s.handle, adapted, key) })
}

// VerifyMessage verifies one complete message and signature.
func (s *sessionLease) VerifyMessage(parameter any, data, signature []byte) error {
	return s.call("C_VerifyMessage", func(module raw.Module) error { return module.VerifyMessage(s.handle, parameter, data, signature) })
}

// VerifyMessageBegin starts multipart message verification.
func (s *sessionLease) VerifyMessageBegin(parameter any) error {
	return s.call("C_VerifyMessageBegin", func(module raw.Module) error { return module.VerifyMessageBegin(s.handle, parameter) })
}

// VerifyMessageNext verifies the next message part and associated signature data.
func (s *sessionLease) VerifyMessageNext(parameter any, data, signature []byte) error {
	return s.call("C_VerifyMessageNext", func(module raw.Module) error { return module.VerifyMessageNext(s.handle, parameter, data, signature) })
}

// MessageVerifyFinal releases state for the active message-verification operation.
func (s *sessionLease) MessageVerifyFinal() error {
	return s.call("C_MessageVerifyFinal", func(module raw.Module) error { return module.MessageVerifyFinal(s.handle) })
}

// PKCS #11 3.2 operations.

// EncapsulateKey performs PKCS #11 3.2 KEM encapsulation, returning ciphertext
// and the newly created secret-key handle.
func (s *sessionLease) EncapsulateKey(mechanisms []*raw.Mechanism, publicKey raw.ObjectHandle, attributes []*raw.Attribute) ([]byte, raw.ObjectHandle, error) {
	adaptedMechanisms, err := normalizeVendorMechanisms(s.currentDevice(), "C_EncapsulateKey", mechanisms)
	if err != nil {
		return nil, 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(s.currentDevice(), "C_EncapsulateKey", attributes)
	if err != nil {
		return nil, 0, err
	}
	type result struct {
		ciphertext []byte
		secret     raw.ObjectHandle
	}
	value, err := sessionValue(s, "C_EncapsulateKey", func(module raw.Module) (result, error) {
		ciphertext, secret, callErr := module.EncapsulateKey(s.handle, adaptedMechanisms, publicKey, adaptedAttributes)
		return result{ciphertext: ciphertext, secret: secret}, callErr
	})
	if err == nil {
		s.invalidateCache()
	}
	return value.ciphertext, value.secret, err
}

// DecapsulateKey performs PKCS #11 3.2 KEM decapsulation and returns the newly
// created secret-key handle.
func (s *sessionLease) DecapsulateKey(mechanisms []*raw.Mechanism, privateKey raw.ObjectHandle, ciphertext []byte, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	adaptedMechanisms, err := normalizeVendorMechanisms(s.currentDevice(), "C_DecapsulateKey", mechanisms)
	if err != nil {
		return 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(s.currentDevice(), "C_DecapsulateKey", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_DecapsulateKey", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.DecapsulateKey(s.handle, adaptedMechanisms, privateKey, ciphertext, adaptedAttributes)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// VerifySignatureInit initializes PKCS #11 3.2 signature-first verification.
func (s *sessionLease) VerifySignatureInit(mechanisms []*raw.Mechanism, key raw.ObjectHandle, signature []byte) error {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_VerifySignatureInit", mechanisms)
	if err != nil {
		return err
	}
	return s.call("C_VerifySignatureInit", func(module raw.Module) error {
		return module.VerifySignatureInit(s.handle, adapted, key, signature)
	})
}

// VerifySignature verifies data after the signature was supplied at initialization.
func (s *sessionLease) VerifySignature(data []byte) error {
	return s.call("C_VerifySignature", func(module raw.Module) error { return module.VerifySignature(s.handle, data) })
}

// VerifySignatureUpdate supplies another part to signature-first verification.
func (s *sessionLease) VerifySignatureUpdate(data []byte) error {
	return s.call("C_VerifySignatureUpdate", func(module raw.Module) error { return module.VerifySignatureUpdate(s.handle, data) })
}

// VerifySignatureFinal completes multipart signature-first verification.
func (s *sessionLease) VerifySignatureFinal() error {
	return s.call("C_VerifySignatureFinal", func(module raw.Module) error { return module.VerifySignatureFinal(s.handle) })
}

// GetSessionValidationFlags returns PKCS #11 3.2 validation status for the requested type.
func (s *sessionLease) GetSessionValidationFlags(typ raw.ValidationFlagsType) (raw.Flags, error) {
	return sessionValue(s, "C_GetSessionValidationFlags", func(module raw.Module) (raw.Flags, error) {
		return module.GetSessionValidationFlags(s.handle, typ)
	})
}

// AsyncComplete retrieves completion data for an asynchronous function.
func (s *sessionLease) AsyncComplete(functionName string, result *raw.AsyncData) error {
	return s.call("C_AsyncComplete", func(module raw.Module) error { return module.AsyncComplete(s.handle, functionName, result) })
}

// AsyncGetID returns the implementation-defined ID of an asynchronous function.
func (s *sessionLease) AsyncGetID(functionName string) (uint, error) {
	return sessionValue(s, "C_AsyncGetID", func(module raw.Module) (uint, error) {
		return module.AsyncGetID(s.handle, functionName)
	})
}

// AsyncJoin associates this session with an existing asynchronous operation.
func (s *sessionLease) AsyncJoin(functionName string, id uint, data []byte) error {
	return s.call("C_AsyncJoin", func(module raw.Module) error { return module.AsyncJoin(s.handle, functionName, id, data) })
}

// WrapKeyAuthenticated performs PKCS #11 3.2 authenticated key wrapping.
func (s *sessionLease) WrapKeyAuthenticated(mechanisms []*raw.Mechanism, wrappingKey, key raw.ObjectHandle, associatedData []byte) ([]byte, error) {
	adapted, err := normalizeVendorMechanisms(s.currentDevice(), "C_WrapKeyAuthenticated", mechanisms)
	if err != nil {
		return nil, err
	}
	return sessionValue(s, "C_WrapKeyAuthenticated", func(module raw.Module) ([]byte, error) {
		return module.WrapKeyAuthenticated(s.handle, adapted, wrappingKey, key, associatedData)
	})
}

// UnwrapKeyAuthenticated performs PKCS #11 3.2 authenticated unwrapping and
// creates a new key object from the normalized template.
func (s *sessionLease) UnwrapKeyAuthenticated(mechanisms []*raw.Mechanism, unwrappingKey raw.ObjectHandle, wrapped []byte, attributes []*raw.Attribute, associatedData []byte) (raw.ObjectHandle, error) {
	adaptedMechanisms, err := normalizeVendorMechanisms(s.currentDevice(), "C_UnwrapKeyAuthenticated", mechanisms)
	if err != nil {
		return 0, err
	}
	adaptedAttributes, err := normalizeVendorTemplate(s.currentDevice(), "C_UnwrapKeyAuthenticated", attributes)
	if err != nil {
		return 0, err
	}
	value, err := sessionValue(s, "C_UnwrapKeyAuthenticated", func(module raw.Module) (raw.ObjectHandle, error) {
		return module.UnwrapKeyAuthenticated(s.handle, adaptedMechanisms, unwrappingKey, wrapped, adaptedAttributes, associatedData)
	})
	if err == nil {
		s.invalidateCache()
	}
	return value, err
}

// invalidateCache conservatively clears all token cache entries after a
// successful operation that may create, mutate, or destroy an object.
func (s *sessionLease) invalidateCache() {
	if s != nil && s.pool != nil && s.pool.owner != nil {
		s.pool.owner.cache.invalidate()
	}
}
