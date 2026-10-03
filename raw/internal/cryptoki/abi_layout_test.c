/*
 * Compile-time conformance checks for the pinned OASIS PKCS #11 3.2 headers.
 *
 * This translation unit validates the pinned ABI shared by both native
 * backends. The default cgo backend includes the same headers through its C
 * bridge, while the PureGo fallback reproduces the validated layouts and
 * function-table slots in Go. These assertions protect both implementations.
 *
 * The checks prove the compiler/header layout. They cannot prove that a vendor
 * module honestly returns a table of the version or size it advertises.
 */

#include <stddef.h>
#include "platform.h"

#define STATIC_ASSERT(name, expr) \
  typedef char static_assert_##name[(expr) ? 1 : -1]

#define NEXT_OFFSET(type, previous, current) \
  STATIC_ASSERT(current##_contiguous, \
    offsetof(CK_FUNCTION_LIST_3_2, current) == \
    offsetof(CK_FUNCTION_LIST_3_2, previous) + sizeof(type))

STATIC_ASSERT(version_is_32,
  CRYPTOKI_VERSION_MAJOR == 3 && CRYPTOKI_VERSION_MINOR == 2);
STATIC_ASSERT(v32_starts_like_v30,
  offsetof(CK_FUNCTION_LIST_3_2, C_Initialize) ==
  offsetof(CK_FUNCTION_LIST_3_0, C_Initialize));
STATIC_ASSERT(v32_encapsulate_after_v30,
  offsetof(CK_FUNCTION_LIST_3_2, C_EncapsulateKey) ==
  sizeof(CK_FUNCTION_LIST_3_0));

NEXT_OFFSET(CK_C_EncapsulateKey, C_EncapsulateKey, C_DecapsulateKey);
NEXT_OFFSET(CK_C_DecapsulateKey, C_DecapsulateKey, C_VerifySignatureInit);
NEXT_OFFSET(CK_C_VerifySignatureInit, C_VerifySignatureInit, C_VerifySignature);
NEXT_OFFSET(CK_C_VerifySignature, C_VerifySignature, C_VerifySignatureUpdate);
NEXT_OFFSET(CK_C_VerifySignatureUpdate, C_VerifySignatureUpdate, C_VerifySignatureFinal);
NEXT_OFFSET(CK_C_VerifySignatureFinal, C_VerifySignatureFinal, C_GetSessionValidationFlags);
NEXT_OFFSET(CK_C_GetSessionValidationFlags, C_GetSessionValidationFlags, C_AsyncComplete);
NEXT_OFFSET(CK_C_AsyncComplete, C_AsyncComplete, C_AsyncGetID);
NEXT_OFFSET(CK_C_AsyncGetID, C_AsyncGetID, C_AsyncJoin);
NEXT_OFFSET(CK_C_AsyncJoin, C_AsyncJoin, C_WrapKeyAuthenticated);
NEXT_OFFSET(CK_C_WrapKeyAuthenticated, C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated);
STATIC_ASSERT(v32_tail_contiguous,
  sizeof(CK_FUNCTION_LIST_3_2) ==
  offsetof(CK_FUNCTION_LIST_3_2, C_UnwrapKeyAuthenticated) +
  sizeof(CK_C_UnwrapKeyAuthenticated));


/*
 * Windows Cryptoki uses the LLP64 data model (32-bit unsigned long, 64-bit
 * pointers) together with one-byte packing. These checks run only when Clang
 * is targeting Windows; merely defining CRYPTOKI_FORCE_WIN32 on a Unix target
 * is useful for packing checks but cannot emulate the width of unsigned long.
 */
#ifdef _WIN32
STATIC_ASSERT(win_ulong_is_32, sizeof(CK_ULONG) == 4);
STATIC_ASSERT(win_pointer_is_64, sizeof(void *) == 8);
STATIC_ASSERT(win_info_size, sizeof(CK_INFO) == 72);
STATIC_ASSERT(win_info_flags, offsetof(CK_INFO, flags) == 34);
STATIC_ASSERT(win_slot_info_size, sizeof(CK_SLOT_INFO) == 104);
STATIC_ASSERT(win_token_info_size, sizeof(CK_TOKEN_INFO) == 160);
STATIC_ASSERT(win_session_info_size, sizeof(CK_SESSION_INFO) == 16);
STATIC_ASSERT(win_mechanism_info_size, sizeof(CK_MECHANISM_INFO) == 12);
STATIC_ASSERT(win_attribute_size, sizeof(CK_ATTRIBUTE) == 16);
STATIC_ASSERT(win_attribute_value, offsetof(CK_ATTRIBUTE, pValue) == 4);
STATIC_ASSERT(win_attribute_length, offsetof(CK_ATTRIBUTE, ulValueLen) == 12);
STATIC_ASSERT(win_mechanism_size, sizeof(CK_MECHANISM) == 16);
STATIC_ASSERT(win_mechanism_parameter, offsetof(CK_MECHANISM, pParameter) == 4);
STATIC_ASSERT(win_mechanism_length, offsetof(CK_MECHANISM, ulParameterLen) == 12);
STATIC_ASSERT(win_interface_size, sizeof(CK_INTERFACE) == 20);
STATIC_ASSERT(win_interface_function_list, offsetof(CK_INTERFACE, pFunctionList) == 8);
STATIC_ASSERT(win_interface_flags, offsetof(CK_INTERFACE, flags) == 16);
STATIC_ASSERT(win_initialize_args_size, sizeof(CK_C_INITIALIZE_ARGS) == 44);
STATIC_ASSERT(win_initialize_flags, offsetof(CK_C_INITIALIZE_ARGS, flags) == 32);
STATIC_ASSERT(win_initialize_reserved, offsetof(CK_C_INITIALIZE_ARGS, pReserved) == 36);
STATIC_ASSERT(win_pss_size, sizeof(CK_RSA_PKCS_PSS_PARAMS) == 12);
STATIC_ASSERT(win_oaep_size, sizeof(CK_RSA_PKCS_OAEP_PARAMS) == 24);
STATIC_ASSERT(win_oaep_source_data, offsetof(CK_RSA_PKCS_OAEP_PARAMS, pSourceData) == 12);
STATIC_ASSERT(win_oaep_source_length, offsetof(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen) == 20);
STATIC_ASSERT(win_aes_ctr_size, sizeof(CK_AES_CTR_PARAMS) == 20);
STATIC_ASSERT(win_gcm_size, sizeof(CK_GCM_PARAMS) == 32);
STATIC_ASSERT(win_ecdh_size, sizeof(CK_ECDH1_DERIVE_PARAMS) == 28);
STATIC_ASSERT(win_eddsa_size, sizeof(CK_EDDSA_PARAMS) == 13);
STATIC_ASSERT(win_sign_context_size, sizeof(CK_SIGN_ADDITIONAL_CONTEXT) == 16);
STATIC_ASSERT(win_hash_sign_context_size, sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT) == 20);
STATIC_ASSERT(win_async_size, sizeof(CK_ASYNC_DATA) == 24);
STATIC_ASSERT(win_function_list_first, offsetof(CK_FUNCTION_LIST, C_Initialize) == 2);
STATIC_ASSERT(win_function_list_size, sizeof(CK_FUNCTION_LIST) == 546);
STATIC_ASSERT(win_function_list_30_first, offsetof(CK_FUNCTION_LIST_3_0, C_GetInterfaceList) == 546);
STATIC_ASSERT(win_function_list_30_size, sizeof(CK_FUNCTION_LIST_3_0) == 738);
STATIC_ASSERT(win_function_list_32_first, offsetof(CK_FUNCTION_LIST_3_2, C_EncapsulateKey) == 738);
STATIC_ASSERT(win_function_list_32_last, offsetof(CK_FUNCTION_LIST_3_2, C_UnwrapKeyAuthenticated) == 826);
STATIC_ASSERT(win_function_list_32_size, sizeof(CK_FUNCTION_LIST_3_2) == 834);
#endif

#undef NEXT_OFFSET
#undef STATIC_ASSERT
