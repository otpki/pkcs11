package raw

import "context"

// Module is the transport-independent PKCS #11 module interface.
// *Ctx implements it for local native libraries and proxy clients implement it
// for remote targets. Implementations must preserve normal Cryptoki session,
// handle, login, and multipart-operation state.
type Module interface {
	Path() string
	Interface() InterfaceInfo
	Version() Version
	Supports(Version) bool
	SetOutputBufferPolicy(policy OutputBufferPolicy)
	Destroy()

	Initialize() error
	InitializeLegacy() error
	InitializeWithFlags(flags uint) error
	Finalize() error

	GetInfo() (Info, error)
	GetFunctionList() (FunctionListInfo, error)
	GetInterface(name string, version *Version, flags uint) (FunctionListInfo, error)
	GetInterfaceList() ([]InterfaceInfo, error)
	GetSlotList(tokenPresent bool) ([]SlotID, error)
	GetSlotInfo(slot SlotID) (SlotInfo, error)
	GetTokenInfo(slot SlotID) (TokenInfo, error)
	GetMechanismList(slot SlotID) ([]MechanismType, error)
	GetMechanismInfo(slot SlotID, mechanism MechanismType) (MechanismInfo, error)
	InitToken(slot SlotID, pin []byte, label string) error

	InitPIN(session SessionHandle, pin []byte) error
	SetPIN(session SessionHandle, oldPIN, newPIN []byte) error
	OpenSession(slot SlotID, flags uint) (SessionHandle, error)
	CloseSession(session SessionHandle) error
	CloseAllSessions(slot SlotID) error
	GetSessionInfo(session SessionHandle) (SessionInfo, error)
	GetOperationState(session SessionHandle) ([]byte, error)
	SetOperationState(session SessionHandle, state []byte, encryptionKey, authenticationKey ObjectHandle) error
	Login(session SessionHandle, userType uint, pin []byte) error
	LoginUser(session SessionHandle, userType uint, pin []byte, username string) error
	Logout(session SessionHandle) error
	SessionCancel(session SessionHandle, flags uint) error
	GetFunctionStatus(session SessionHandle) error
	CancelFunction(session SessionHandle) error
	WaitForSlotEvent(flags uint) (SlotID, error)

	CreateObject(session SessionHandle, attributes []*Attribute) (ObjectHandle, error)
	CopyObject(session SessionHandle, object ObjectHandle, attributes []*Attribute) (ObjectHandle, error)
	DestroyObject(session SessionHandle, object ObjectHandle) error
	GetObjectSize(session SessionHandle, object ObjectHandle) (uint, error)
	GetAttributeValue(session SessionHandle, object ObjectHandle, attributes []*Attribute) ([]*Attribute, error)
	SetAttributeValue(session SessionHandle, object ObjectHandle, attributes []*Attribute) error
	FindObjectsInit(session SessionHandle, attributes []*Attribute) error
	FindObjects(session SessionHandle, maxObjects int) ([]ObjectHandle, bool, error)
	FindObjectsFinal(session SessionHandle) error
	FindAllObjects(session SessionHandle, attributes []*Attribute, batchSize int) ([]ObjectHandle, error)

	EncryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	Encrypt(session SessionHandle, plaintext []byte) ([]byte, error)
	EncryptUpdate(session SessionHandle, plaintext []byte) ([]byte, error)
	EncryptFinal(session SessionHandle) ([]byte, error)
	DecryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	Decrypt(session SessionHandle, ciphertext []byte) ([]byte, error)
	DecryptUpdate(session SessionHandle, ciphertext []byte) ([]byte, error)
	DecryptFinal(session SessionHandle) ([]byte, error)
	DigestInit(session SessionHandle, mechanisms []*Mechanism) error
	Digest(session SessionHandle, data []byte) ([]byte, error)
	DigestUpdate(session SessionHandle, data []byte) error
	DigestKey(session SessionHandle, key ObjectHandle) error
	DigestFinal(session SessionHandle) ([]byte, error)
	SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	Sign(session SessionHandle, data []byte) ([]byte, error)
	SignUpdate(session SessionHandle, data []byte) error
	SignFinal(session SessionHandle) ([]byte, error)
	SignRecoverInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	SignRecover(session SessionHandle, data []byte) ([]byte, error)
	VerifyInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	Verify(session SessionHandle, data, signature []byte) error
	VerifyUpdate(session SessionHandle, data []byte) error
	VerifyFinal(session SessionHandle, signature []byte) error
	VerifyRecoverInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	VerifyRecover(session SessionHandle, signature []byte) ([]byte, error)
	DigestEncryptUpdate(session SessionHandle, data []byte) ([]byte, error)
	DecryptDigestUpdate(session SessionHandle, data []byte) ([]byte, error)
	SignEncryptUpdate(session SessionHandle, data []byte) ([]byte, error)
	DecryptVerifyUpdate(session SessionHandle, data []byte) ([]byte, error)

	GenerateKey(session SessionHandle, mechanisms []*Mechanism, attributes []*Attribute) (ObjectHandle, error)
	GenerateKeyPair(session SessionHandle, mechanisms []*Mechanism, publicAttributes, privateAttributes []*Attribute) (ObjectHandle, ObjectHandle, error)
	WrapKey(session SessionHandle, mechanisms []*Mechanism, wrappingKey, key ObjectHandle) ([]byte, error)
	UnwrapKey(session SessionHandle, mechanisms []*Mechanism, unwrappingKey ObjectHandle, wrapped []byte, attributes []*Attribute) (ObjectHandle, error)
	DeriveKey(session SessionHandle, mechanisms []*Mechanism, baseKey ObjectHandle, attributes []*Attribute) (ObjectHandle, error)
	SeedRandom(session SessionHandle, seed []byte) error
	GenerateRandom(session SessionHandle, length int) ([]byte, error)

	MessageEncryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	EncryptMessage(session SessionHandle, parameter any, associatedData, plaintext []byte) ([]byte, error)
	EncryptMessageBegin(session SessionHandle, parameter any, associatedData []byte) error
	EncryptMessageNext(session SessionHandle, parameter any, plaintext []byte, flags uint) ([]byte, error)
	MessageEncryptFinal(session SessionHandle) error
	MessageDecryptInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	DecryptMessage(session SessionHandle, parameter any, associatedData, ciphertext []byte) ([]byte, error)
	DecryptMessageBegin(session SessionHandle, parameter any, associatedData []byte) error
	DecryptMessageNext(session SessionHandle, parameter any, ciphertext []byte, flags uint) ([]byte, error)
	MessageDecryptFinal(session SessionHandle) error
	MessageSignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	SignMessage(session SessionHandle, parameter any, data []byte) ([]byte, error)
	SignMessageBegin(session SessionHandle, parameter any) error
	SignMessageNext(session SessionHandle, parameter any, data []byte) ([]byte, error)
	MessageSignFinal(session SessionHandle) error
	MessageVerifyInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	VerifyMessage(session SessionHandle, parameter any, data, signature []byte) error
	VerifyMessageBegin(session SessionHandle, parameter any) error
	VerifyMessageNext(session SessionHandle, parameter any, data, signature []byte) error
	MessageVerifyFinal(session SessionHandle) error

	EncapsulateKey(session SessionHandle, mechanisms []*Mechanism, publicKey ObjectHandle, attributes []*Attribute) ([]byte, ObjectHandle, error)
	DecapsulateKey(session SessionHandle, mechanisms []*Mechanism, privateKey ObjectHandle, ciphertext []byte, attributes []*Attribute) (ObjectHandle, error)
	VerifySignatureInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle, signature []byte) error
	VerifySignature(session SessionHandle, data []byte) error
	VerifySignatureUpdate(session SessionHandle, data []byte) error
	VerifySignatureFinal(session SessionHandle) error
	GetSessionValidationFlags(session SessionHandle, typ ValidationFlagsType) (Flags, error)
	AsyncComplete(session SessionHandle, functionName string, result *AsyncData) error
	AsyncGetID(session SessionHandle, functionName string) (uint, error)
	AsyncJoin(session SessionHandle, functionName string, id uint, data []byte) error
	WrapKeyAuthenticated(session SessionHandle, mechanisms []*Mechanism, wrappingKey, key ObjectHandle, associatedData []byte) ([]byte, error)
	UnwrapKeyAuthenticated(session SessionHandle, mechanisms []*Mechanism, unwrappingKey ObjectHandle, wrapped []byte, attributes []*Attribute, associatedData []byte) (ObjectHandle, error)
}

var _ Module = (*Ctx)(nil)

// ContextualModule lets managed callers bind a cancellation/deadline context
// to a sequence of otherwise context-free Cryptoki method calls. Local native
// modules may ignore it because an in-flight vendor call is not portably
// cancellable; remote modules use it for dialing, request deadlines, and
// disconnect handling.
type ContextualModule interface {
	WithContext(context.Context, func(Module) error) error
}
