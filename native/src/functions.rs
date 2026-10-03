// Interface discovery is local and works before initialization, without config
// or network access. All versions share one initialized client and session state.
const INTERFACE_NAME: &[u8] = b"PKCS 11\0";
struct InterfaceList([CK_INTERFACE; 4]);
// SAFETY: These pointers refer only to immutable static names and function
// tables. PKCS#11 callers must not write to the returned library-owned memory.
unsafe impl Sync for InterfaceList {}
static INTERFACES: InterfaceList = InterfaceList([
    CK_INTERFACE { pInterfaceName: INTERFACE_NAME.as_ptr().cast_mut(), pFunctionList: ptr::addr_of!(FUNCTIONS_3_2).cast_mut().cast(), flags: 0 },
    CK_INTERFACE { pInterfaceName: INTERFACE_NAME.as_ptr().cast_mut(), pFunctionList: ptr::addr_of!(FUNCTIONS_3_1).cast_mut().cast(), flags: 0 },
    CK_INTERFACE { pInterfaceName: INTERFACE_NAME.as_ptr().cast_mut(), pFunctionList: ptr::addr_of!(FUNCTIONS_3_0).cast_mut().cast(), flags: 0 },
    CK_INTERFACE { pInterfaceName: INTERFACE_NAME.as_ptr().cast_mut(), pFunctionList: ptr::addr_of!(FUNCTIONS).cast_mut().cast(), flags: 0 },
]);

#[no_mangle]
pub unsafe extern "C" fn C_GetInterfaceList(out: CK_INTERFACE_PTR, count: CK_ULONG_PTR) -> CK_RV {
    entry(|| copy_output(&INTERFACES.0, out, count))
}
#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(name: CK_UTF8CHAR_PTR, version: CK_VERSION_PTR,
    out: CK_INTERFACE_PTR_PTR, flags: CK_FLAGS) -> CK_RV {
    entry(|| {
        if out.is_null() || flags != 0 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
        if !name.is_null() && std::ffi::CStr::from_ptr(name.cast()).to_bytes_with_nul() != INTERFACE_NAME {
            return Err(Error::rv(CKR_ARGUMENTS_BAD));
        }
        let requested = if version.is_null() { None } else { Some(read(version)?) };
        for interface in &INTERFACES.0 {
            let actual: CK_VERSION = read(interface.pFunctionList.cast())?;
            if requested.map_or(true, |v| v.major == actual.major && v.minor == actual.minor) {
                return write(out, ptr::from_ref(interface).cast_mut());
            }
        }
        Err(Error::rv(CKR_ARGUMENTS_BAD))
    })
}

// Keep unsupported entries callable, not NULL. The table types check their
// signatures, including Windows packing and CK_ULONG width.

function!(C_InitToken(_slotID: CK_SLOT_ID, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG, _pLabel: CK_UTF8CHAR_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_InitPIN(_hSession: CK_SESSION_HANDLE, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_SetPIN(_hSession: CK_SESSION_HANDLE, _pOldPin: CK_UTF8CHAR_PTR, _ulOldLen: CK_ULONG, _pNewPin: CK_UTF8CHAR_PTR, _ulNewLen: CK_ULONG) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_GetOperationState(_hSession: CK_SESSION_HANDLE, _pOperationState: CK_BYTE_PTR, _pulOperationStateLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_SetOperationState(_hSession: CK_SESSION_HANDLE, _pOperationState: CK_BYTE_PTR, _ulOperationStateLen: CK_ULONG, _hEncryptionKey: CK_OBJECT_HANDLE, _hAuthenticationKey: CK_OBJECT_HANDLE) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_CopyObject(_hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR, _ulCount: CK_ULONG, _phNewObject: CK_OBJECT_HANDLE_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_SignRecoverInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_SignRecover(_hSession: CK_SESSION_HANDLE, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pSignature: CK_BYTE_PTR, _pulSignatureLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_VerifyRecoverInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_VerifyRecover(_hSession: CK_SESSION_HANDLE, _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG, _pData: CK_BYTE_PTR, _pulDataLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_DigestEncryptUpdate(_hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG, _pEncryptedPart: CK_BYTE_PTR, _pulEncryptedPartLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_DecryptDigestUpdate(_hSession: CK_SESSION_HANDLE, _pEncryptedPart: CK_BYTE_PTR, _ulEncryptedPartLen: CK_ULONG, _pPart: CK_BYTE_PTR, _pulPartLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_SignEncryptUpdate(_hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG, _pEncryptedPart: CK_BYTE_PTR, _pulEncryptedPartLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_DecryptVerifyUpdate(_hSession: CK_SESSION_HANDLE, _pEncryptedPart: CK_BYTE_PTR, _ulEncryptedPartLen: CK_ULONG, _pPart: CK_BYTE_PTR, _pulPartLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_WrapKey(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hWrappingKey: CK_OBJECT_HANDLE, _hKey: CK_OBJECT_HANDLE, _pWrappedKey: CK_BYTE_PTR, _pulWrappedKeyLen: CK_ULONG_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_UnwrapKey(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hUnwrappingKey: CK_OBJECT_HANDLE, _pWrappedKey: CK_BYTE_PTR, _ulWrappedKeyLen: CK_ULONG, _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_DeriveKey(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hBaseKey: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});
function!(C_GetFunctionStatus(_hSession: CK_SESSION_HANDLE) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_PARALLEL))
});
function!(C_CancelFunction(_hSession: CK_SESSION_HANDLE) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_PARALLEL))
});
function!(C_WaitForSlotEvent(_flags: CK_FLAGS, _pSlot: CK_SLOT_ID_PTR, _pRserved: CK_VOID_PTR) |_c| {
    Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED))
});

// These need message-specific pointer translation, persistent async state, or
// key-creation/output-buffer handling. Leave them explicit rather than guessing.
macro_rules! unsupported {
    ($name:ident($($arg:ident: $ty:ty),* $(,)?)) => {
        function!($name($($arg: $ty),*) |_c| { Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED)) });
    };
}
unsupported!(C_MessageEncryptInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE));
unsupported!(C_EncryptMessage(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG, _pPlaintext: CK_BYTE_PTR, _ulPlaintextLen: CK_ULONG, _pCiphertext: CK_BYTE_PTR, _pulCiphertextLen: CK_ULONG_PTR));
unsupported!(C_EncryptMessageBegin(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG));
unsupported!(C_EncryptMessageNext(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pPlaintextPart: CK_BYTE_PTR, _ulPlaintextPartLen: CK_ULONG, _pCiphertextPart: CK_BYTE_PTR, _pulCiphertextPartLen: CK_ULONG_PTR, _flags: CK_FLAGS));
unsupported!(C_MessageEncryptFinal(_hSession: CK_SESSION_HANDLE));
unsupported!(C_MessageDecryptInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE));
unsupported!(C_DecryptMessage(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG, _pCiphertext: CK_BYTE_PTR, _ulCiphertextLen: CK_ULONG, _pPlaintext: CK_BYTE_PTR, _pulPlaintextLen: CK_ULONG_PTR));
unsupported!(C_DecryptMessageBegin(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG));
unsupported!(C_DecryptMessageNext(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pCiphertextPart: CK_BYTE_PTR, _ulCiphertextPartLen: CK_ULONG, _pPlaintextPart: CK_BYTE_PTR, _pulPlaintextPartLen: CK_ULONG_PTR, _flags: CK_FLAGS));
unsupported!(C_MessageDecryptFinal(_hSession: CK_SESSION_HANDLE));
unsupported!(C_MessageSignInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE));
unsupported!(C_SignMessage(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pSignature: CK_BYTE_PTR, _pulSignatureLen: CK_ULONG_PTR));
unsupported!(C_SignMessageBegin(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG));
unsupported!(C_SignMessageNext(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pSignature: CK_BYTE_PTR, _pulSignatureLen: CK_ULONG_PTR));
unsupported!(C_MessageSignFinal(_hSession: CK_SESSION_HANDLE));
unsupported!(C_MessageVerifyInit(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE));
unsupported!(C_VerifyMessage(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG));
unsupported!(C_VerifyMessageBegin(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG));
unsupported!(C_VerifyMessageNext(_hSession: CK_SESSION_HANDLE, _pParameter: CK_VOID_PTR, _ulParameterLen: CK_ULONG, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG));
unsupported!(C_MessageVerifyFinal(_hSession: CK_SESSION_HANDLE));
unsupported!(C_EncapsulateKey(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hPublicKey: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _pCiphertext: CK_BYTE_PTR, _pulCiphertextLen: CK_ULONG_PTR, _phKey: CK_OBJECT_HANDLE_PTR));
unsupported!(C_DecapsulateKey(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hPrivateKey: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _pCiphertext: CK_BYTE_PTR, _ulCiphertextLen: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR));
unsupported!(C_AsyncComplete(_hSession: CK_SESSION_HANDLE, _pFunctionName: CK_UTF8CHAR_PTR, _pResult: CK_ASYNC_DATA_PTR));
unsupported!(C_AsyncGetID(_hSession: CK_SESSION_HANDLE, _pFunctionName: CK_UTF8CHAR_PTR, _pulID: CK_ULONG_PTR));
unsupported!(C_AsyncJoin(_hSession: CK_SESSION_HANDLE, _pFunctionName: CK_UTF8CHAR_PTR, _ulID: CK_ULONG, _pData: CK_BYTE_PTR, _ulData: CK_ULONG));
unsupported!(C_WrapKeyAuthenticated(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hWrappingKey: CK_OBJECT_HANDLE, _hKey: CK_OBJECT_HANDLE, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG, _pWrappedKey: CK_BYTE_PTR, _pulWrappedKeyLen: CK_ULONG_PTR));
unsupported!(C_UnwrapKeyAuthenticated(_hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hUnwrappingKey: CK_OBJECT_HANDLE, _pWrappedKey: CK_BYTE_PTR, _ulWrappedKeyLen: CK_ULONG, _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _pAssociatedData: CK_BYTE_PTR, _ulAssociatedDataLen: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR));

include!(concat!(env!("OUT_DIR"), "/tables.rs"));
