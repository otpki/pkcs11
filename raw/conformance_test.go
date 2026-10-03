package raw

import (
	"reflect"
	"testing"
)

// TestCryptokiFunctionSurface prevents a PKCS #11 func from being
// dropped from the raw implementation. The list mirrors the complete
// function table generated from the pinned OASIS 3.2 header. Both transports (purego/cgo)
// invoke these same methods.
func TestCryptokiFunctionSurface(t *testing.T) {
	expected := []string{
		"AsyncComplete",
		"AsyncGetID",
		"AsyncJoin",
		"CancelFunction",
		"CloseAllSessions",
		"CloseSession",
		"CopyObject",
		"CreateObject",
		"DecapsulateKey",
		"Decrypt",
		"DecryptDigestUpdate",
		"DecryptFinal",
		"DecryptInit",
		"DecryptMessage",
		"DecryptMessageBegin",
		"DecryptMessageNext",
		"DecryptUpdate",
		"DecryptVerifyUpdate",
		"DeriveKey",
		"DestroyObject",
		"Digest",
		"DigestEncryptUpdate",
		"DigestFinal",
		"DigestInit",
		"DigestKey",
		"DigestUpdate",
		"EncapsulateKey",
		"Encrypt",
		"EncryptFinal",
		"EncryptInit",
		"EncryptMessage",
		"EncryptMessageBegin",
		"EncryptMessageNext",
		"EncryptUpdate",
		"Finalize",
		"FindObjects",
		"FindObjectsFinal",
		"FindObjectsInit",
		"GenerateKey",
		"GenerateKeyPair",
		"GenerateRandom",
		"GetAttributeValue",
		"GetFunctionList",
		"GetFunctionStatus",
		"GetInfo",
		"GetInterface",
		"GetInterfaceList",
		"GetMechanismInfo",
		"GetMechanismList",
		"GetObjectSize",
		"GetOperationState",
		"GetSessionInfo",
		"GetSessionValidationFlags",
		"GetSlotInfo",
		"GetSlotList",
		"GetTokenInfo",
		"InitPIN",
		"InitToken",
		"Initialize",
		"Login",
		"LoginUser",
		"Logout",
		"MessageDecryptFinal",
		"MessageDecryptInit",
		"MessageEncryptFinal",
		"MessageEncryptInit",
		"MessageSignFinal",
		"MessageSignInit",
		"MessageVerifyFinal",
		"MessageVerifyInit",
		"OpenSession",
		"SeedRandom",
		"SessionCancel",
		"SetAttributeValue",
		"SetOperationState",
		"SetPIN",
		"Sign",
		"SignEncryptUpdate",
		"SignFinal",
		"SignInit",
		"SignMessage",
		"SignMessageBegin",
		"SignMessageNext",
		"SignRecover",
		"SignRecoverInit",
		"SignUpdate",
		"UnwrapKey",
		"UnwrapKeyAuthenticated",
		"Verify",
		"VerifyFinal",
		"VerifyInit",
		"VerifyMessage",
		"VerifyMessageBegin",
		"VerifyMessageNext",
		"VerifyRecover",
		"VerifyRecoverInit",
		"VerifySignature",
		"VerifySignatureFinal",
		"VerifySignatureInit",
		"VerifySignatureUpdate",
		"VerifyUpdate",
		"WaitForSlotEvent",
		"WrapKey",
		"WrapKeyAuthenticated",
	}
	typ := reflect.TypeFor[*Ctx]()
	for _, name := range expected {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("raw.Ctx is missing C_%s", name)
		}
	}
}

// this is just a spot check to make sure our generators aren't spitting out junk
func TestPKCS1132ConstantValues(t *testing.T) {
	tests := map[string]struct {
		got  uint
		want uint
	}{
		"CKF_SEED_RANDOM_REQUIRED":        {CKF_SEED_RANDOM_REQUIRED, 0x02000000},
		"CKF_ASYNC_SESSION_SUPPORTED":     {CKF_ASYNC_SESSION_SUPPORTED, 0x04000000},
		"CKM_ECDH_X_AES_KEY_WRAP":         {CKM_ECDH_X_AES_KEY_WRAP, 0x00004038},
		"CKM_ECDH_COF_AES_KEY_WRAP":       {CKM_ECDH_COF_AES_KEY_WRAP, 0x00004039},
		"CKM_PUB_KEY_FROM_PRIV_KEY":       {CKM_PUB_KEY_FROM_PRIV_KEY, 0x0000403a},
		"CKR_TOKEN_RESOURCE_EXCEEDED":     {CKR_TOKEN_RESOURCE_EXCEEDED, 0x00000201},
		"CKR_KEY_EXHAUSTED":               {CKR_KEY_EXHAUSTED, 0x00000203},
		"CKR_PENDING":                     {CKR_PENDING, 0x00000204},
		"CKR_SESSION_ASYNC_NOT_SUPPORTED": {CKR_SESSION_ASYNC_NOT_SUPPORTED, 0x00000205},
		"CKR_SEED_RANDOM_REQUIRED":        {CKR_SEED_RANDOM_REQUIRED, 0x00000206},
		"CKR_OPERATION_NOT_VALIDATED":     {CKR_OPERATION_NOT_VALIDATED, 0x00000207},
		"CKR_TOKEN_NOT_INITIALIZED":       {CKR_TOKEN_NOT_INITIALIZED, 0x00000208},
		"CKR_PARAMETER_SET_NOT_SUPPORTED": {CKR_PARAMETER_SET_NOT_SUPPORTED, 0x00000209},
	}
	for name, test := range tests {
		if test.got != test.want {
			t.Errorf("%s = %#x, want %#x", name, test.got, test.want)
		}
	}
}
