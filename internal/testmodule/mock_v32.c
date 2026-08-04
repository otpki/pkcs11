#include "platform.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static CK_BBOOL initialized = CK_FALSE;
static CK_FUNCTION_LIST_3_2 mock_functions;
static CK_UTF8CHAR interface_name[] = "PKCS 11";
static CK_INTERFACE mock_interface = {interface_name, &mock_functions, 0};
static CK_BYTE_PTR saved_verify_signature = NULL;
static CK_ULONG saved_verify_signature_len = 0;

static CK_RV mock_C_Initialize(CK_VOID_PTR args) {
  (void)args;
  if (initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  initialized = CK_TRUE;
  return CKR_OK;
}

static CK_RV mock_C_Finalize(CK_VOID_PTR reserved) {
  (void)reserved;
  if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
  initialized = CK_FALSE;
  return CKR_OK;
}

static void padded(CK_UTF8CHAR *target, size_t length, const char *value) {
  size_t n = strlen(value);
  if (n > length) n = length;
  memset(target, ' ', length);
  memcpy(target, value, n);
}

static CK_RV mock_C_GetInfo(CK_INFO_PTR info) {
  if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  info->cryptokiVersion.major = 3;
  info->cryptokiVersion.minor = 2;
  padded(info->manufacturerID, sizeof(info->manufacturerID), "OTPKI PureGo Test");
  padded(info->libraryDescription, sizeof(info->libraryDescription), "PKCS11 3.2 ABI Fixture");
  info->libraryVersion.major = 3;
  info->libraryVersion.minor = 2;
  return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
  if (!list) return CKR_ARGUMENTS_BAD;
  *list = (CK_FUNCTION_LIST_PTR)&mock_functions;
  return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR list, CK_ULONG_PTR count) {
  if (!count) return CKR_ARGUMENTS_BAD;
  if (!list) {
    *count = 1;
    return CKR_OK;
  }
  if (*count < 1) {
    *count = 1;
    return CKR_BUFFER_TOO_SMALL;
  }
  list[0] = mock_interface;
  *count = 1;
  return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR iface, CK_FLAGS flags) {
  if (!iface || flags != 0) return CKR_ARGUMENTS_BAD;
  if (name && strcmp((const char *)name, "PKCS 11") != 0) return CKR_ARGUMENTS_BAD;
  if (version && (version->major != 3 || version->minor != 2)) return CKR_ARGUMENTS_BAD;
  *iface = &mock_interface;
  return CKR_OK;
}

static CK_RV mock_C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session) {
  (void)application;
  (void)notify;
  if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if (slot != 7 || !session || !(flags & CKF_SERIAL_SESSION)) return CKR_ARGUMENTS_BAD;
  *session = 0x77;
  return CKR_OK;
}

static CK_RV mock_C_CloseSession(CK_SESSION_HANDLE session) {
  return session == 0x77 ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

static CK_RV mock_C_LoginUser(CK_SESSION_HANDLE session, CK_USER_TYPE type, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR username, CK_ULONG username_len) {
  if (session != 0x77 || type != CKU_USER) return CKR_ARGUMENTS_BAD;
  if (pin_len != 4 || memcmp(pin, "1234", 4) != 0) return CKR_PIN_INCORRECT;
  if (username_len != 5 || memcmp(username, "alice", 5) != 0) return CKR_ARGUMENTS_BAD;
  return CKR_OK;
}

static CK_RV mock_C_MessageSignInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  return session == 0x77 && mechanism && mechanism->mechanism == CKM_SHA256_HMAC && key == 9 ? CKR_OK : CKR_ARGUMENTS_BAD;
}

static CK_RV mock_C_SignMessage(CK_SESSION_HANDLE session, CK_VOID_PTR parameter, CK_ULONG parameter_len,
                                CK_BYTE_PTR data, CK_ULONG data_len,
                                CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  (void)parameter;
  (void)parameter_len;
  if (session != 0x77 || !data || !signature_len) return CKR_ARGUMENTS_BAD;
  CK_ULONG required = data_len + 1;
  if (!signature) {
    *signature_len = required;
    return CKR_OK;
  }
  if (*signature_len < required) {
    *signature_len = required;
    return CKR_BUFFER_TOO_SMALL;
  }
  signature[0] = 0x32;
  memcpy(signature + 1, data, data_len);
  *signature_len = required;
  return CKR_OK;
}


static CK_RV mock_C_MessageSignFinal(CK_SESSION_HANDLE session) {
  return session == 0x77 ? CKR_OK : CKR_SESSION_HANDLE_INVALID;
}

static CK_RV mock_C_EncapsulateKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                                   CK_OBJECT_HANDLE public_key, CK_ATTRIBUTE_PTR attributes,
                                   CK_ULONG attribute_count, CK_BYTE_PTR ciphertext,
                                   CK_ULONG_PTR ciphertext_len, CK_OBJECT_HANDLE_PTR key) {
  (void)attributes;
  (void)attribute_count;
  if (session != 0x77 || !mechanism || mechanism->mechanism != CKM_ML_KEM || public_key != 11 || !ciphertext_len || !key) return CKR_ARGUMENTS_BAD;
  if (!ciphertext) {
    *ciphertext_len = 4;
    return CKR_OK;
  }
  if (*ciphertext_len < 4) {
    *ciphertext_len = 4;
    return CKR_BUFFER_TOO_SMALL;
  }
  ciphertext[0] = 1; ciphertext[1] = 2; ciphertext[2] = 3; ciphertext[3] = 4;
  *ciphertext_len = 4;
  *key = 0x1234;
  return CKR_OK;
}

static CK_RV mock_C_DecapsulateKey(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                                   CK_OBJECT_HANDLE private_key, CK_ATTRIBUTE_PTR attributes,
                                   CK_ULONG attribute_count, CK_BYTE_PTR ciphertext,
                                   CK_ULONG ciphertext_len, CK_OBJECT_HANDLE_PTR key) {
  (void)attributes;
  (void)attribute_count;
  if (session != 0x77 || !mechanism || mechanism->mechanism != CKM_ML_KEM || private_key != 12 || !ciphertext || ciphertext_len != 4 || !key) return CKR_ARGUMENTS_BAD;
  *key = 0x5678;
  return CKR_OK;
}

static CK_RV mock_C_VerifySignatureInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key, CK_BYTE_PTR signature,
                                        CK_ULONG signature_len) {
  if (session != 0x77 || !mechanism || key != 13 || !signature || signature_len != 3) return CKR_ARGUMENTS_BAD;
  if (signature[0] != 1 || signature[1] != 2 || signature[2] != 3) return CKR_SIGNATURE_INVALID;
  saved_verify_signature = signature;
  saved_verify_signature_len = signature_len;
  return CKR_OK;
}

static CK_RV mock_C_VerifySignature(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len) {
  if (session != 0x77 || !data || data_len != 2 || data[0] != 'o' || data[1] != 'k') return CKR_SIGNATURE_INVALID;
  if (!saved_verify_signature || saved_verify_signature_len != 3 ||
      saved_verify_signature[0] != 1 || saved_verify_signature[1] != 2 || saved_verify_signature[2] != 3) return CKR_SIGNATURE_INVALID;
  saved_verify_signature = NULL;
  saved_verify_signature_len = 0;
  return CKR_OK;
}

static CK_RV mock_C_VerifySignatureUpdate(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len) {
  return session == 0x77 && data && data_len != 0 ? CKR_OK : CKR_ARGUMENTS_BAD;
}

static CK_RV mock_C_VerifySignatureFinal(CK_SESSION_HANDLE session) {
  if (session != 0x77) return CKR_SESSION_HANDLE_INVALID;
  if (!saved_verify_signature || saved_verify_signature_len != 3 ||
      saved_verify_signature[0] != 1 || saved_verify_signature[1] != 2 || saved_verify_signature[2] != 3) return CKR_SIGNATURE_INVALID;
  saved_verify_signature = NULL;
  saved_verify_signature_len = 0;
  return CKR_OK;
}

static CK_RV mock_C_GetSessionValidationFlags(CK_SESSION_HANDLE session, CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR flags) {
  if (session != 0x77 || type != CKS_LAST_VALIDATION_OK || !flags) return CKR_ARGUMENTS_BAD;
  *flags = 0xa5;
  return CKR_OK;
}

static CK_RV mock_C_AsyncComplete(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR name, CK_ASYNC_DATA_PTR result) {
  if (session != 0x77 || !name || strcmp((const char *)name, "C_Mock") != 0 || !result) return CKR_ARGUMENTS_BAD;
  result->ulVersion = 2;
  result->hObject = 0x44;
  result->hAdditionalObject = 0x55;
  if (result->pValue && result->ulValue >= 3) {
    result->pValue[0] = 9; result->pValue[1] = 8; result->pValue[2] = 7;
    result->ulValue = 3;
  }
  return CKR_OK;
}

static CK_RV mock_C_AsyncGetID(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR name, CK_ULONG_PTR id) {
  if (session != 0x77 || !name || strcmp((const char *)name, "C_Mock") != 0 || !id) return CKR_ARGUMENTS_BAD;
  *id = 42;
  return CKR_OK;
}

static CK_RV mock_C_AsyncJoin(CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR name, CK_ULONG id, CK_BYTE_PTR data, CK_ULONG data_len) {
  return session == 0x77 && name && strcmp((const char *)name, "C_Mock") == 0 && id == 42 && data && data_len == 2 ? CKR_OK : CKR_ARGUMENTS_BAD;
}

static CK_RV mock_C_WrapKeyAuthenticated(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                                         CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                                         CK_BYTE_PTR aad, CK_ULONG aad_len,
                                         CK_BYTE_PTR wrapped, CK_ULONG_PTR wrapped_len) {
  if (session != 0x77 || !mechanism || wrapping_key != 14 || key != 15 || !aad || aad_len != 3 || !wrapped_len) return CKR_ARGUMENTS_BAD;
  if (!wrapped) { *wrapped_len = 3; return CKR_OK; }
  if (*wrapped_len < 3) { *wrapped_len = 3; return CKR_BUFFER_TOO_SMALL; }
  wrapped[0] = 6; wrapped[1] = 5; wrapped[2] = 4; *wrapped_len = 3;
  return CKR_OK;
}

static CK_RV mock_C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                                           CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped,
                                           CK_ULONG wrapped_len, CK_ATTRIBUTE_PTR attributes,
                                           CK_ULONG attribute_count, CK_BYTE_PTR aad,
                                           CK_ULONG aad_len, CK_OBJECT_HANDLE_PTR key) {
  (void)attributes;
  (void)attribute_count;
  if (session != 0x77 || !mechanism || unwrapping_key != 16 || !wrapped || wrapped_len != 3 || !aad || aad_len != 3 || !key) return CKR_ARGUMENTS_BAD;
  *key = 0x9abc;
  return CKR_OK;
}

static CK_FUNCTION_LIST_3_2 mock_functions = {
  .version = {3, 2},
  .C_Initialize = mock_C_Initialize,
  .C_Finalize = mock_C_Finalize,
  .C_GetInfo = mock_C_GetInfo,
  .C_GetFunctionList = C_GetFunctionList,
  .C_OpenSession = mock_C_OpenSession,
  .C_CloseSession = mock_C_CloseSession,
  .C_GetInterfaceList = C_GetInterfaceList,
  .C_GetInterface = C_GetInterface,
  .C_LoginUser = mock_C_LoginUser,
  .C_MessageSignInit = mock_C_MessageSignInit,
  .C_SignMessage = mock_C_SignMessage,
  .C_MessageSignFinal = mock_C_MessageSignFinal,
  .C_EncapsulateKey = mock_C_EncapsulateKey,
  .C_DecapsulateKey = mock_C_DecapsulateKey,
  .C_VerifySignatureInit = mock_C_VerifySignatureInit,
  .C_VerifySignature = mock_C_VerifySignature,
  .C_VerifySignatureUpdate = mock_C_VerifySignatureUpdate,
  .C_VerifySignatureFinal = mock_C_VerifySignatureFinal,
  .C_GetSessionValidationFlags = mock_C_GetSessionValidationFlags,
  .C_AsyncComplete = mock_C_AsyncComplete,
  .C_AsyncGetID = mock_C_AsyncGetID,
  .C_AsyncJoin = mock_C_AsyncJoin,
  .C_WrapKeyAuthenticated = mock_C_WrapKeyAuthenticated,
  .C_UnwrapKeyAuthenticated = mock_C_UnwrapKeyAuthenticated,
};
