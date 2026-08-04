#include "platform.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static atomic_int mock_initialized = 0;
static atomic_int mock_logged_in = 0;
static atomic_ulong mock_next_session = 1;
static atomic_ulong mock_open_sessions = 0;
static atomic_ulong mock_max_open_sessions = 0;
static atomic_ulong mock_login_calls = 0;
static atomic_ulong mock_logout_calls = 0;
static atomic_ulong mock_random_counter = 1;
static atomic_int mock_encrypt_initialized = 0;
static atomic_ulong mock_slow_object_reads = 0;

#define MOCK_MAX_SESSIONS 4096
#define MOCK_DIAG_LOGIN_CALLS      (CKM_VENDOR_DEFINED + 0x7f01UL)
#define MOCK_DIAG_LOGOUT_CALLS     (CKM_VENDOR_DEFINED + 0x7f02UL)
#define MOCK_DIAG_MAX_SESSIONS     (CKM_VENDOR_DEFINED + 0x7f03UL)
#define MOCK_DIAG_OPEN_SESSIONS    (CKM_VENDOR_DEFINED + 0x7f04UL)
#define MOCK_DIAG_SLOW_OBJECT_READS (CKM_VENDOR_DEFINED + 0x7f05UL)
#define MOCK_SLOW_RANDOM_LENGTH    4093UL
#ifndef MOCK_PROTECTED_AUTH_PATH
#define MOCK_PROTECTED_AUTH_PATH 0
#endif
static pthread_mutex_t mock_session_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t mock_session_threads[MOCK_MAX_SESSIONS];
static unsigned char mock_session_active[MOCK_MAX_SESSIONS];

#define MOCK_MAX_OBJECTS 4096
#define MOCK_MAX_LABEL 128
#define MOCK_MAX_ID 128

typedef struct mock_object {
  unsigned char active;
  CK_OBJECT_CLASS class_value;
  CK_KEY_TYPE key_type;
  CK_BBOOL token;
  CK_BBOOL private_value;
  CK_SESSION_HANDLE owner_session;
  CK_ULONG label_len;
  CK_BYTE label[MOCK_MAX_LABEL];
  CK_ULONG id_len;
  CK_BYTE id[MOCK_MAX_ID];
} mock_object;

typedef struct mock_find_state {
  unsigned char active;
  CK_BBOOL has_class;
  CK_OBJECT_CLASS class_value;
  CK_BBOOL has_key_type;
  CK_KEY_TYPE key_type;
  CK_BBOOL has_token;
  CK_BBOOL token;
  CK_ULONG label_len;
  CK_BYTE label[MOCK_MAX_LABEL];
  CK_ULONG id_len;
  CK_BYTE id[MOCK_MAX_ID];
  CK_ULONG cursor;
} mock_find_state;

static pthread_mutex_t mock_object_mutex = PTHREAD_MUTEX_INITIALIZER;
static mock_object mock_objects[MOCK_MAX_OBJECTS];
static mock_find_state mock_finds[MOCK_MAX_SESSIONS];
static atomic_ulong mock_next_object = 1;

static CK_RV mock_require_session(CK_SESSION_HANDLE session) {
  if (session == 0 || session >= MOCK_MAX_SESSIONS) return CKR_SESSION_HANDLE_INVALID;
  pthread_mutex_lock(&mock_session_mutex);
  int active = mock_session_active[session] != 0;
  int same_thread = active && pthread_equal(mock_session_threads[session], pthread_self());
  pthread_mutex_unlock(&mock_session_mutex);
  if (!active) return CKR_SESSION_HANDLE_INVALID;
  // CKR_GENERAL_ERROR is deliberate: the managed test must not hide a thread
  // affinity violation through session-recovery retries.
  return same_thread ? CKR_OK : CKR_GENERAL_ERROR;
}

static void mock_text(CK_UTF8CHAR *target, size_t length, const char *value) {
  size_t value_len = strlen(value);
  if (value_len > length) value_len = length;
  memset(target, ' ', length);
  memcpy(target, value, value_len);
}

static CK_RV mock_require_initialized(void) {
  return atomic_load(&mock_initialized) ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

static CK_RV mock_C_Initialize(CK_VOID_PTR args) {
  (void)args;
  int expected = 0;
  if (!atomic_compare_exchange_strong(&mock_initialized, &expected, 1)) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }
  atomic_store(&mock_logged_in, 0);
  atomic_store(&mock_encrypt_initialized, 0);
  atomic_store(&mock_open_sessions, 0);
  atomic_store(&mock_max_open_sessions, 0);
  atomic_store(&mock_login_calls, 0);
  atomic_store(&mock_logout_calls, 0);
  atomic_store(&mock_slow_object_reads, 0);
  atomic_store(&mock_next_object, 1);
  pthread_mutex_lock(&mock_object_mutex);
  memset(mock_objects, 0, sizeof(mock_objects));
  memset(mock_finds, 0, sizeof(mock_finds));
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static CK_RV mock_C_Finalize(CK_VOID_PTR reserved) {
  (void)reserved;
  int expected = 1;
  if (!atomic_compare_exchange_strong(&mock_initialized, &expected, 0)) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  atomic_store(&mock_logged_in, 0);
  atomic_store(&mock_encrypt_initialized, 0);
  pthread_mutex_lock(&mock_session_mutex);
  memset(mock_session_active, 0, sizeof(mock_session_active));
  pthread_mutex_unlock(&mock_session_mutex);
  pthread_mutex_lock(&mock_object_mutex);
  memset(mock_objects, 0, sizeof(mock_objects));
  memset(mock_finds, 0, sizeof(mock_finds));
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static CK_RV mock_C_GetInfo(CK_INFO_PTR info) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  info->cryptokiVersion.major = 2;
  info->cryptokiVersion.minor = 40;
  mock_text(info->manufacturerID, sizeof(info->manufacturerID), "OTPKI Test");
  mock_text(info->libraryDescription, sizeof(info->libraryDescription), "OTPKI Mock PKCS11");
  info->libraryVersion.major = 1;
  info->libraryVersion.minor = 0;
  return CKR_OK;
}

static CK_RV mock_C_GetSlotList(CK_BBOOL token_present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count) {
  (void)token_present;
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (!count) return CKR_ARGUMENTS_BAD;
  if (!slots) {
    *count = 1;
    return CKR_OK;
  }
  if (*count < 1) {
    *count = 1;
    return CKR_BUFFER_TOO_SMALL;
  }
  slots[0] = 1;
  *count = 1;
  return CKR_OK;
}

static CK_RV mock_C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  mock_text(info->slotDescription, sizeof(info->slotDescription), "OTPKI Mock Slot");
  mock_text(info->manufacturerID, sizeof(info->manufacturerID), "OTPKI Test");
  info->flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE;
  info->hardwareVersion.major = 1;
  info->firmwareVersion.major = 1;
  return CKR_OK;
}

static CK_RV mock_C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  mock_text(info->label, sizeof(info->label), "OTPKI-MOCK");
  mock_text(info->manufacturerID, sizeof(info->manufacturerID), "OTPKI Test");
  mock_text((CK_UTF8CHAR *)info->model, sizeof(info->model), "MOCK-1");
  mock_text((CK_UTF8CHAR *)info->serialNumber, sizeof(info->serialNumber), "0000000000000001");
  info->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | (MOCK_PROTECTED_AUTH_PATH ? CKF_PROTECTED_AUTHENTICATION_PATH : 0);
  info->ulMaxSessionCount = 64;
  info->ulSessionCount = atomic_load(&mock_open_sessions);
  info->ulMaxRwSessionCount = 64;
  info->ulRwSessionCount = info->ulSessionCount;
  info->ulMaxPinLen = 64;
  info->ulMinPinLen = 1;
  info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  info->hardwareVersion.major = 1;
  info->firmwareVersion.major = 1;
  mock_text((CK_UTF8CHAR *)info->utcTime, sizeof(info->utcTime), "2026072912000000");
  return CKR_OK;
}

static CK_RV mock_C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  if (!count) return CKR_ARGUMENTS_BAD;
  if (!list) {
    *count = 1;
    return CKR_OK;
  }
  if (*count < 1) {
    *count = 1;
    return CKR_BUFFER_TOO_SMALL;
  }
  list[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
  *count = 1;
  return CKR_OK;
}

static CK_RV mock_C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  if (mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
    info->ulMinKeySize = 2048;
    info->ulMaxKeySize = 4096;
    info->flags = CKF_GENERATE_KEY_PAIR;
    return CKR_OK;
  }
  // Vendor-defined mechanism-info entries are diagnostics for the Go tests.
  // They are deliberately omitted from C_GetMechanismList so normal capability
  // discovery is unchanged.
  if (mechanism == MOCK_DIAG_LOGIN_CALLS) {
    info->ulMinKeySize = atomic_load(&mock_login_calls);
    return CKR_OK;
  }
  if (mechanism == MOCK_DIAG_LOGOUT_CALLS) {
    info->ulMinKeySize = atomic_load(&mock_logout_calls);
    return CKR_OK;
  }
  if (mechanism == MOCK_DIAG_MAX_SESSIONS) {
    info->ulMinKeySize = atomic_load(&mock_max_open_sessions);
    return CKR_OK;
  }
  if (mechanism == MOCK_DIAG_OPEN_SESSIONS) {
    info->ulMinKeySize = atomic_load(&mock_open_sessions);
    return CKR_OK;
  }
  if (mechanism == MOCK_DIAG_SLOW_OBJECT_READS) {
    info->ulMinKeySize = atomic_load(&mock_slow_object_reads);
    return CKR_OK;
  }
  return CKR_MECHANISM_INVALID;
}

static CK_RV mock_C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session) {
  (void)application;
  (void)notify;
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  if (!session) return CKR_ARGUMENTS_BAD;
  CK_SESSION_HANDLE handle = atomic_fetch_add(&mock_next_session, 1);
  if (handle == 0 || handle >= MOCK_MAX_SESSIONS) return CKR_SESSION_COUNT;
  pthread_mutex_lock(&mock_session_mutex);
  mock_session_threads[handle] = pthread_self();
  mock_session_active[handle] = 1;
  pthread_mutex_unlock(&mock_session_mutex);
  *session = handle;
  unsigned long opened = atomic_fetch_add(&mock_open_sessions, 1) + 1;
  unsigned long maximum = atomic_load(&mock_max_open_sessions);
  while (opened > maximum &&
         !atomic_compare_exchange_weak(&mock_max_open_sessions, &maximum, opened)) {
  }
  return CKR_OK;
}

static CK_RV mock_C_CloseSession(CK_SESSION_HANDLE session) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  pthread_mutex_lock(&mock_session_mutex);
  mock_session_active[session] = 0;
  pthread_mutex_unlock(&mock_session_mutex);
  pthread_mutex_lock(&mock_object_mutex);
  memset(&mock_finds[session], 0, sizeof(mock_finds[session]));
  for (CK_ULONG i = 1; i < MOCK_MAX_OBJECTS; i++) {
    if (mock_objects[i].active && !mock_objects[i].token && mock_objects[i].owner_session == session) {
      memset(&mock_objects[i], 0, sizeof(mock_objects[i]));
    }
  }
  pthread_mutex_unlock(&mock_object_mutex);
  atomic_fetch_sub(&mock_open_sessions, 1);
  return CKR_OK;
}

static CK_RV mock_C_CloseAllSessions(CK_SLOT_ID slot) {
  if (slot != 1) return CKR_SLOT_ID_INVALID;
  pthread_mutex_lock(&mock_session_mutex);
  memset(mock_session_active, 0, sizeof(mock_session_active));
  pthread_mutex_unlock(&mock_session_mutex);
  atomic_store(&mock_open_sessions, 0);
  return CKR_OK;
}

static CK_RV mock_C_GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!info) return CKR_ARGUMENTS_BAD;
  memset(info, 0, sizeof(*info));
  info->slotID = 1;
  info->state = atomic_load(&mock_logged_in) ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
  info->flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  return CKR_OK;
}

static CK_RV mock_C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (user_type != CKU_USER && user_type != CKU_CONTEXT_SPECIFIC) return CKR_USER_TYPE_INVALID;
  atomic_fetch_add(&mock_login_calls, 1);
  if (MOCK_PROTECTED_AUTH_PATH) {
    if (pin || pin_len != 0) return CKR_ARGUMENTS_BAD;
  } else if (!pin || pin_len != 4 || memcmp(pin, "1234", 4) != 0) {
    return CKR_PIN_INCORRECT;
  }
  if (user_type == CKU_CONTEXT_SPECIFIC) return CKR_OK;
  int expected = 0;
  if (!atomic_compare_exchange_strong(&mock_logged_in, &expected, 1)) return CKR_USER_ALREADY_LOGGED_IN;
  return CKR_OK;
}

static CK_RV mock_C_Logout(CK_SESSION_HANDLE session) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  atomic_fetch_add(&mock_logout_calls, 1);
  int expected = 1;
  if (!atomic_compare_exchange_strong(&mock_logged_in, &expected, 0)) return CKR_USER_NOT_LOGGED_IN;
  return CKR_OK;
}


static CK_RV mock_copy_attribute_value(CK_ATTRIBUTE_PTR attribute, const void *value, CK_ULONG length) {
  if (!attribute) return CKR_ARGUMENTS_BAD;
  if (!attribute->pValue) {
    attribute->ulValueLen = length;
    return CKR_OK;
  }
  if (attribute->ulValueLen < length) {
    attribute->ulValueLen = length;
    return CKR_BUFFER_TOO_SMALL;
  }
  if (length != 0) memcpy(attribute->pValue, value, length);
  attribute->ulValueLen = length;
  return CKR_OK;
}

static CK_RV mock_C_CreateObject(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                                 CK_ULONG count, CK_OBJECT_HANDLE_PTR object_handle) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!object_handle || (count != 0 && !attributes)) return CKR_ARGUMENTS_BAD;

  mock_object object;
  memset(&object, 0, sizeof(object));
  object.class_value = CKO_DATA;
  object.key_type = 0;
  object.token = CK_FALSE;
  object.private_value = CK_FALSE;
  object.owner_session = session;
  for (CK_ULONG i = 0; i < count; i++) {
    CK_ATTRIBUTE_PTR attribute = &attributes[i];
    if (!attribute->pValue && attribute->ulValueLen != 0) return CKR_ATTRIBUTE_VALUE_INVALID;
    switch (attribute->type) {
      case CKA_CLASS:
        if (attribute->ulValueLen != sizeof(CK_OBJECT_CLASS)) return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(&object.class_value, attribute->pValue, sizeof(object.class_value));
        break;
      case CKA_KEY_TYPE:
        if (attribute->ulValueLen != sizeof(CK_KEY_TYPE)) return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(&object.key_type, attribute->pValue, sizeof(object.key_type));
        break;
      case CKA_TOKEN:
        if (attribute->ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(&object.token, attribute->pValue, sizeof(object.token));
        break;
      case CKA_PRIVATE:
        if (attribute->ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
        memcpy(&object.private_value, attribute->pValue, sizeof(object.private_value));
        break;
      case CKA_LABEL:
        if (attribute->ulValueLen > MOCK_MAX_LABEL) return CKR_ATTRIBUTE_VALUE_INVALID;
        object.label_len = attribute->ulValueLen;
        if (object.label_len) memcpy(object.label, attribute->pValue, object.label_len);
        break;
      case CKA_ID:
        if (attribute->ulValueLen > MOCK_MAX_ID) return CKR_ATTRIBUTE_VALUE_INVALID;
        object.id_len = attribute->ulValueLen;
        if (object.id_len) memcpy(object.id, attribute->pValue, object.id_len);
        break;
      default:
        break;
    }
  }

  CK_OBJECT_HANDLE handle = atomic_fetch_add(&mock_next_object, 1);
  if (handle == 0 || handle >= MOCK_MAX_OBJECTS) return CKR_DEVICE_MEMORY;
  object.active = 1;
  pthread_mutex_lock(&mock_object_mutex);
  mock_objects[handle] = object;
  pthread_mutex_unlock(&mock_object_mutex);
  *object_handle = handle;
  return CKR_OK;
}

static CK_RV mock_C_DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object_handle) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (object_handle == 0 || object_handle >= MOCK_MAX_OBJECTS) return CKR_OBJECT_HANDLE_INVALID;
  pthread_mutex_lock(&mock_object_mutex);
  mock_object *object = &mock_objects[object_handle];
  if (!object->active) {
    pthread_mutex_unlock(&mock_object_mutex);
    return CKR_OBJECT_HANDLE_INVALID;
  }
  memset(object, 0, sizeof(*object));
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static CK_RV mock_C_GetObjectSize(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object_handle,
                                  CK_ULONG_PTR size) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!size) return CKR_ARGUMENTS_BAD;
  if (object_handle == 0 || object_handle >= MOCK_MAX_OBJECTS) return CKR_OBJECT_HANDLE_INVALID;
  pthread_mutex_lock(&mock_object_mutex);
  mock_object object = mock_objects[object_handle];
  pthread_mutex_unlock(&mock_object_mutex);
  if (!object.active) return CKR_OBJECT_HANDLE_INVALID;

  static const char slow_label[] = "slow-session-object";
  if (object.label_len == sizeof(slow_label) - 1 &&
      memcmp(object.label, slow_label, sizeof(slow_label) - 1) == 0) {
    atomic_fetch_add(&mock_slow_object_reads, 1);
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 200000000L};
    nanosleep(&delay, NULL);
    pthread_mutex_lock(&mock_object_mutex);
    object = mock_objects[object_handle];
    pthread_mutex_unlock(&mock_object_mutex);
    atomic_fetch_sub(&mock_slow_object_reads, 1);
    if (!object.active) return CKR_OBJECT_HANDLE_INVALID;
  }

  *size = sizeof(object);
  return CKR_OK;
}

static CK_RV mock_C_GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object_handle,
                                      CK_ATTRIBUTE_PTR attributes, CK_ULONG count) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (count != 0 && !attributes) return CKR_ARGUMENTS_BAD;
  if (object_handle == 0 || object_handle >= MOCK_MAX_OBJECTS) return CKR_OBJECT_HANDLE_INVALID;
  pthread_mutex_lock(&mock_object_mutex);
  mock_object object = mock_objects[object_handle];
  pthread_mutex_unlock(&mock_object_mutex);
  if (!object.active) return CKR_OBJECT_HANDLE_INVALID;

  CK_RV overall = CKR_OK;
  for (CK_ULONG i = 0; i < count; i++) {
    CK_ATTRIBUTE_PTR attribute = &attributes[i];
    CK_RV attribute_rv = CKR_OK;
    switch (attribute->type) {
      case CKA_CLASS:
        attribute_rv = mock_copy_attribute_value(attribute, &object.class_value, sizeof(object.class_value));
        break;
      case CKA_KEY_TYPE:
        attribute_rv = mock_copy_attribute_value(attribute, &object.key_type, sizeof(object.key_type));
        break;
      case CKA_TOKEN:
        attribute_rv = mock_copy_attribute_value(attribute, &object.token, sizeof(object.token));
        break;
      case CKA_PRIVATE:
        attribute_rv = mock_copy_attribute_value(attribute, &object.private_value, sizeof(object.private_value));
        break;
      case CKA_LABEL:
        attribute_rv = mock_copy_attribute_value(attribute, object.label, object.label_len);
        break;
      case CKA_ID:
        attribute_rv = mock_copy_attribute_value(attribute, object.id, object.id_len);
        break;
      default:
        attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        attribute_rv = CKR_ATTRIBUTE_TYPE_INVALID;
        break;
    }
    if (overall == CKR_OK && attribute_rv != CKR_OK) overall = attribute_rv;
  }
  return overall;
}

static CK_RV mock_C_FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes,
                                    CK_ULONG count) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (count != 0 && !attributes) return CKR_ARGUMENTS_BAD;
  pthread_mutex_lock(&mock_object_mutex);
  mock_find_state *state = &mock_finds[session];
  if (state->active) {
    pthread_mutex_unlock(&mock_object_mutex);
    return CKR_OPERATION_ACTIVE;
  }
  memset(state, 0, sizeof(*state));
  state->active = 1;
  state->cursor = 1;
  for (CK_ULONG i = 0; i < count; i++) {
    CK_ATTRIBUTE_PTR attribute = &attributes[i];
    switch (attribute->type) {
      case CKA_CLASS:
        if (attribute->ulValueLen != sizeof(CK_OBJECT_CLASS)) { pthread_mutex_unlock(&mock_object_mutex); return CKR_ATTRIBUTE_VALUE_INVALID; }
        memcpy(&state->class_value, attribute->pValue, sizeof(state->class_value));
        state->has_class = CK_TRUE;
        break;
      case CKA_KEY_TYPE:
        if (attribute->ulValueLen != sizeof(CK_KEY_TYPE)) { pthread_mutex_unlock(&mock_object_mutex); return CKR_ATTRIBUTE_VALUE_INVALID; }
        memcpy(&state->key_type, attribute->pValue, sizeof(state->key_type));
        state->has_key_type = CK_TRUE;
        break;
      case CKA_TOKEN:
        if (attribute->ulValueLen != sizeof(CK_BBOOL)) { pthread_mutex_unlock(&mock_object_mutex); return CKR_ATTRIBUTE_VALUE_INVALID; }
        memcpy(&state->token, attribute->pValue, sizeof(state->token));
        state->has_token = CK_TRUE;
        break;
      case CKA_LABEL:
        if (attribute->ulValueLen > MOCK_MAX_LABEL) { pthread_mutex_unlock(&mock_object_mutex); return CKR_ATTRIBUTE_VALUE_INVALID; }
        state->label_len = attribute->ulValueLen;
        if (state->label_len) memcpy(state->label, attribute->pValue, state->label_len);
        break;
      case CKA_ID:
        if (attribute->ulValueLen > MOCK_MAX_ID) { pthread_mutex_unlock(&mock_object_mutex); return CKR_ATTRIBUTE_VALUE_INVALID; }
        state->id_len = attribute->ulValueLen;
        if (state->id_len) memcpy(state->id, attribute->pValue, state->id_len);
        break;
      default:
        break;
    }
  }
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static int mock_object_matches(const mock_object *object, const mock_find_state *state,
                               CK_SESSION_HANDLE session) {
  if (!object->active) return 0;
  if (state->has_class && object->class_value != state->class_value) return 0;
  if (state->has_key_type && object->key_type != state->key_type) return 0;
  if (state->has_token && object->token != state->token) return 0;
  if (state->label_len && (object->label_len != state->label_len || memcmp(object->label, state->label, state->label_len) != 0)) return 0;
  if (state->id_len && (object->id_len != state->id_len || memcmp(object->id, state->id, state->id_len) != 0)) return 0;
  return 1;
}

static CK_RV mock_C_FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                                CK_ULONG maximum, CK_ULONG_PTR count) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!count || (maximum != 0 && !objects)) return CKR_ARGUMENTS_BAD;
  pthread_mutex_lock(&mock_object_mutex);
  mock_find_state *state = &mock_finds[session];
  if (!state->active) { pthread_mutex_unlock(&mock_object_mutex); return CKR_OPERATION_NOT_INITIALIZED; }
  CK_ULONG written = 0;
  for (CK_ULONG i = state->cursor; i < MOCK_MAX_OBJECTS && written < maximum; i++) {
    state->cursor = i + 1;
    if (mock_object_matches(&mock_objects[i], state, session)) objects[written++] = i;
  }
  *count = written;
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static CK_RV mock_C_FindObjectsFinal(CK_SESSION_HANDLE session) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  pthread_mutex_lock(&mock_object_mutex);
  if (!mock_finds[session].active) { pthread_mutex_unlock(&mock_object_mutex); return CKR_OPERATION_NOT_INITIALIZED; }
  memset(&mock_finds[session], 0, sizeof(mock_finds[session]));
  pthread_mutex_unlock(&mock_object_mutex);
  return CKR_OK;
}

static CK_RV mock_C_EncryptInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  (void)mechanism;
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (key == 0 || key >= MOCK_MAX_OBJECTS) return CKR_KEY_HANDLE_INVALID;
  pthread_mutex_lock(&mock_object_mutex);
  int valid_key = mock_objects[key].active != 0;
  pthread_mutex_unlock(&mock_object_mutex);
  if (!valid_key) return CKR_KEY_HANDLE_INVALID;
  atomic_store(&mock_encrypt_initialized, 1);
  return CKR_OK;
}

static CK_RV mock_C_Encrypt(CK_SESSION_HANDLE session, CK_BYTE_PTR input, CK_ULONG input_len,
                            CK_BYTE_PTR output, CK_ULONG_PTR output_len) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!atomic_load(&mock_encrypt_initialized)) return CKR_OPERATION_NOT_INITIALIZED;
  if (!input || !output_len) return CKR_ARGUMENTS_BAD;
  // Simulate a provider that rejects the standard NULL sizing probe and loses
  // its active operation when that invalid call is attempted. Compatibility
  // mode must therefore skip the probe rather than retry after it fails.
  if (!output) {
    atomic_store(&mock_encrypt_initialized, 0);
    return CKR_ARGUMENTS_BAD;
  }
  if (*output_len < input_len) {
    *output_len = input_len;
    return CKR_BUFFER_TOO_SMALL;
  }
  memcpy(output, input, input_len);
  *output_len = input_len;
  atomic_store(&mock_encrypt_initialized, 0);
  return CKR_OK;
}

static CK_RV mock_C_SeedRandom(CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seed_len) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  for (CK_ULONG i = 0; i < seed_len; i++) atomic_fetch_add(&mock_random_counter, seed[i] + 1);
  return CKR_OK;
}

static CK_RV mock_C_GenerateRandom(CK_SESSION_HANDLE session, CK_BYTE_PTR output, CK_ULONG output_len) {
  CK_RV rv = mock_require_initialized();
  if (rv != CKR_OK) return rv;
  rv = mock_require_session(session);
  if (rv != CKR_OK) return rv;
  if (!output && output_len != 0) return CKR_ARGUMENTS_BAD;
  if (output_len == MOCK_SLOW_RANDOM_LENGTH) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 150000000};
    nanosleep(&delay, NULL);
  }
  uint64_t state = atomic_fetch_add(&mock_random_counter, output_len + 1);
  for (CK_ULONG i = 0; i < output_len; i++) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    output[i] = (CK_BYTE)(state & 0xff);
  }
  return CKR_OK;
}

static CK_RV mock_C_GetFunctionStatus(CK_SESSION_HANDLE session) {
  CK_RV rv = mock_require_session(session);
  return rv == CKR_OK ? CKR_FUNCTION_NOT_PARALLEL : rv;
}

static CK_RV mock_C_CancelFunction(CK_SESSION_HANDLE session) {
  CK_RV rv = mock_require_session(session);
  return rv == CKR_OK ? CKR_FUNCTION_NOT_PARALLEL : rv;
}

static CK_RV mock_C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved) {
  (void)slot;
  (void)reserved;
  if (flags & CKF_DONT_BLOCK) return CKR_NO_EVENT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST mock_functions;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
  if (!list) return CKR_ARGUMENTS_BAD;
  *list = &mock_functions;
  return CKR_OK;
}

static CK_FUNCTION_LIST mock_functions = {
  .version = {2, 40},
  .C_Initialize = mock_C_Initialize,
  .C_Finalize = mock_C_Finalize,
  .C_GetInfo = mock_C_GetInfo,
  .C_GetFunctionList = C_GetFunctionList,
  .C_GetSlotList = mock_C_GetSlotList,
  .C_GetSlotInfo = mock_C_GetSlotInfo,
  .C_GetTokenInfo = mock_C_GetTokenInfo,
  .C_GetMechanismList = mock_C_GetMechanismList,
  .C_GetMechanismInfo = mock_C_GetMechanismInfo,
  .C_OpenSession = mock_C_OpenSession,
  .C_CloseSession = mock_C_CloseSession,
  .C_CloseAllSessions = mock_C_CloseAllSessions,
  .C_GetSessionInfo = mock_C_GetSessionInfo,
  .C_Login = mock_C_Login,
  .C_Logout = mock_C_Logout,
  .C_CreateObject = mock_C_CreateObject,
  .C_DestroyObject = mock_C_DestroyObject,
  .C_GetObjectSize = mock_C_GetObjectSize,
  .C_GetAttributeValue = mock_C_GetAttributeValue,
  .C_FindObjectsInit = mock_C_FindObjectsInit,
  .C_FindObjects = mock_C_FindObjects,
  .C_FindObjectsFinal = mock_C_FindObjectsFinal,
  .C_EncryptInit = mock_C_EncryptInit,
  .C_Encrypt = mock_C_Encrypt,
  .C_SeedRandom = mock_C_SeedRandom,
  .C_GenerateRandom = mock_C_GenerateRandom,
  .C_GetFunctionStatus = mock_C_GetFunctionStatus,
  .C_CancelFunction = mock_C_CancelFunction,
  .C_WaitForSlotEvent = mock_C_WaitForSlotEvent,
};
