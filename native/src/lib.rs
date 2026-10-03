//! Small PKCS#11 3.2 client for pkcs11-proxy. The server owns the HSM and keys.
#![allow(non_snake_case)]
#[cfg(not(target_endian = "little"))]
compile_error!("The native client currently supports little-endian platforms only.");

mod config;
mod marshal;
mod wire;

use cryptoki_sys::*;
use marshal::*;
use std::{panic::{catch_unwind, AssertUnwindSafe}, ptr, sync::{Mutex, atomic::{AtomicU32, Ordering}}};
use wire::{Client, Pending, Value, MAX_DATA};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
struct Error { rv: CK_RV, message: Option<&'static str> }
impl Error {
    fn rv(rv: CK_RV) -> Self { Self { rv, message: None } }
    fn config(message: &'static str) -> Self { Self { rv: CKR_ARGUMENTS_BAD, message: Some(message) } }
    fn protocol() -> Self { Self { rv: CKR_DEVICE_ERROR, message: Some("invalid or incompatible proxy response") } }
    fn transport() -> Self { Self { rv: CKR_DEVICE_ERROR, message: Some("proxy connection failed; do not blindly retry a signing or key-creation request") } }
}

static STATE: Mutex<Option<Client>> = Mutex::new(None);
static OWNER: AtomicU32 = AtomicU32::new(0);

fn entry(f: impl FnOnce() -> Result<()>) -> CK_RV {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CKR_OK,
        Ok(Err(error)) => {
            // Only our fixed messages are logged. Never print PINs, request JSON,
            // private keys, or an untrusted error message returned by the server.
            if let Some(message) = error.message {
                use std::io::Write;
                let _ = writeln!(std::io::stderr().lock(), "pkcs11-proxy-client: {message}");
            }
            error.rv
        }
        Err(_) => CKR_GENERAL_ERROR,
    }
}
fn process_check() -> Result<()> {
    let owner = OWNER.load(Ordering::Acquire);
    if owner != 0 && owner != std::process::id() { Err(Error::rv(CKR_CANT_LOCK)) } else { Ok(()) }
}
fn with_client(f: impl FnOnce(&mut Client) -> Result<()>) -> CK_RV {
    entry(|| {
        process_check()?;
        let mut state = STATE.lock().map_err(|_| Error::rv(CKR_GENERAL_ERROR))?;
        let client = state.as_mut().ok_or(Error::rv(CKR_CRYPTOKI_NOT_INITIALIZED))?;
        if client.dead { return Err(Error::rv(CKR_DEVICE_ERROR)); }
        f(client)
    })
}
macro_rules! function {
    ($name:ident($($arg:ident: $ty:ty),* $(,)?) |$client:ident| $body:block) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name($($arg: $ty),*) -> CK_RV {
            with_client(|$client| $body)
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(out: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    entry(|| write(out, ptr::addr_of!(FUNCTIONS).cast_mut()))
}
#[no_mangle]
pub unsafe extern "C" fn C_Initialize(args: CK_VOID_PTR) -> CK_RV {
    entry(|| {
        process_check()?;
        OWNER.store(std::process::id(), Ordering::Release);
        let mut state = STATE.lock().map_err(|_| Error::rv(CKR_GENERAL_ERROR))?;
        if state.is_some() { return Err(Error::rv(CKR_CRYPTOKI_ALREADY_INITIALIZED)); }
        if !args.is_null() {
            let args: CK_C_INITIALIZE_ARGS = read(args.cast())?;
            if !args.pReserved.is_null() || args.flags & !(CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0 {
                return Err(Error::rv(CKR_ARGUMENTS_BAD));
            }
            let callbacks = [matches!(args.CreateMutex, Some(_)), matches!(args.DestroyMutex, Some(_)), matches!(args.LockMutex, Some(_)), matches!(args.UnlockMutex, Some(_))];
            if callbacks.iter().any(|v| *v) && !callbacks.iter().all(|v| *v) { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
            if callbacks.iter().all(|v| *v) && args.flags & CKF_OS_LOCKING_OK == 0 { return Err(Error::rv(CKR_CANT_LOCK)); }
        }
        *state = Some(Client::open(config::Config::load()?)?);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn C_Finalize(reserved: CK_VOID_PTR) -> CK_RV {
    entry(|| {
        if !reserved.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
        process_check()?;
        let mut state = STATE.lock().map_err(|_| Error::rv(CKR_GENERAL_ERROR))?;
        let mut client = state.take().ok_or(Error::rv(CKR_CRYPTOKI_NOT_INITIALIZED))?;
        // Always discard local sessions, even if the broker has already gone away.
        let result = client.call("Finalize", vec![]).map(|_| ());
        if !client.dead { let _ = client.call("@destroy", vec![]); }
        result
    })
}
// Older tables report their own version. The directly exported C_GetInfo uses
// the newest interface; obtaining another table never changes global state.
unsafe fn get_info(p: CK_INFO_PTR, major: u8, minor: u8) -> CK_RV {
    with_client(|_c| write(p, CK_INFO {
        cryptokiVersion: CK_VERSION { major, minor },
        manufacturerID: padded("OTPKI"), flags: 0,
        libraryDescription: padded("PKCS11 proxy client"),
        libraryVersion: CK_VERSION { major: 0, minor: 1 },
    }))
}
#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(p: CK_INFO_PTR) -> CK_RV { get_info(p, 3, 2) }
unsafe extern "C" fn get_info_2_40(p: CK_INFO_PTR) -> CK_RV { get_info(p, 2, 40) }
unsafe extern "C" fn get_info_3_0(p: CK_INFO_PTR) -> CK_RV { get_info(p, 3, 0) }
unsafe extern "C" fn get_info_3_1(p: CK_INFO_PTR) -> CK_RV { get_info(p, 3, 1) }
function!(C_GetSlotList(present: CK_BBOOL, p: CK_SLOT_ID_PTR, n: CK_ULONG_PTR) |c| {
    if n.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let r = c.call("GetSlotList", vec![Value::boolean(present != 0)])?;
    let slots = r.result(0)?.list_ref()?.iter().map(|v| ulong(v.num()?)).collect::<Result<Vec<_>>>()?;
    copy_output(&slots, p, n)
});
function!(C_GetSlotInfo(slot: CK_SLOT_ID, p: CK_SLOT_INFO_PTR) |c| {
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let r = c.call("GetSlotInfo", vec![Value::number(slot as u64)])?; let v = r.result(0)?;
    write(p, CK_SLOT_INFO { slotDescription: padded(v.field("SlotDescription")?.text()?),
        manufacturerID: padded(v.field("ManufacturerID")?.text()?), flags: number(v, "Flags")?,
        hardwareVersion: version(v.field("HardwareVersion")?)?, firmwareVersion: version(v.field("FirmwareVersion")?)? })
});
function!(C_GetTokenInfo(slot: CK_SLOT_ID, p: CK_TOKEN_INFO_PTR) |c| {
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let r = c.call("GetTokenInfo", vec![Value::number(slot as u64)])?; let v = r.result(0)?;
    write(p, CK_TOKEN_INFO {
        label: padded(v.field("Label")?.text()?), manufacturerID: padded(v.field("ManufacturerID")?.text()?),
        model: padded(v.field("Model")?.text()?), serialNumber: padded(v.field("SerialNumber")?.text()?),
        flags: number(v, "Flags")? & !(CKF_DUAL_CRYPTO_OPERATIONS | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_ASYNC_SESSION_SUPPORTED),
        ulMaxSessionCount: available(v, "MaxSessionCount", c.ulong_size)?,
        ulSessionCount: available(v, "SessionCount", c.ulong_size)?,
        ulMaxRwSessionCount: available(v, "MaxRwSessionCount", c.ulong_size)?,
        ulRwSessionCount: available(v, "RwSessionCount", c.ulong_size)?,
        ulMaxPinLen: number(v, "MaxPinLen")?, ulMinPinLen: number(v, "MinPinLen")?,
        ulTotalPublicMemory: available(v, "TotalPublicMemory", c.ulong_size)?,
        ulFreePublicMemory: available(v, "FreePublicMemory", c.ulong_size)?,
        ulTotalPrivateMemory: available(v, "TotalPrivateMemory", c.ulong_size)?,
        ulFreePrivateMemory: available(v, "FreePrivateMemory", c.ulong_size)?,
        hardwareVersion: version(v.field("HardwareVersion")?)?, firmwareVersion: version(v.field("FirmwareVersion")?)?,
        utcTime: padded(v.field("UTCTime")?.text()?),
    })
});
function!(C_GetMechanismList(slot: CK_SLOT_ID, p: CK_MECHANISM_TYPE_PTR, n: CK_ULONG_PTR) |c| {
    if n.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let r = c.call("GetMechanismList", vec![Value::number(slot as u64)])?;
    let mut mechanisms = Vec::new();
    for v in r.result(0)?.list_ref()? {
        // Unrepresentable vendor IDs are not part of this client's allowlist.
        if let Ok(m) = CK_MECHANISM_TYPE::try_from(v.num()?) {
            if supported_mechanism(m) { mechanisms.push(m); }
        }
    }
    copy_output(&mechanisms, p, n)
});
function!(C_GetMechanismInfo(slot: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, p: CK_MECHANISM_INFO_PTR) |c| {
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if !supported_mechanism(mechanism) { return Err(Error::rv(CKR_MECHANISM_INVALID)); }
    let r = c.call("GetMechanismInfo", vec![Value::number(slot as u64), Value::number(mechanism as u64)])?; let v = r.result(0)?;
    write(p, CK_MECHANISM_INFO { ulMinKeySize: number(v, "MinKeySize")?, ulMaxKeySize: number(v, "MaxKeySize")?,
        flags: number(v, "Flags")? & (CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST | CKF_SIGN | CKF_VERIFY | CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_F_2M | CKF_EC_ECPARAMETERS | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS) })
});
function!(C_OpenSession(slot: CK_SLOT_ID, flags: CK_FLAGS, _application: CK_VOID_PTR, notify: CK_NOTIFY, out: CK_SESSION_HANDLE_PTR) |c| {
    if out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if notify.is_some() { return Err(Error::rv(CKR_FUNCTION_NOT_SUPPORTED)); }
    if flags & CKF_SERIAL_SESSION == 0 { return Err(Error::rv(CKR_SESSION_PARALLEL_NOT_SUPPORTED)); }
    if flags & !(CKF_SERIAL_SESSION | CKF_RW_SESSION) != 0 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if c.sessions.len() >= 128 { return Err(Error::rv(CKR_SESSION_COUNT)); }
    let r = c.call("OpenSession", vec![Value::number(slot as u64), Value::number(flags as u64)])?;
    let session = ulong(r.result(0)?.num()?)?;
    c.sessions.insert(session, slot); write(out, session)
});
function!(C_CloseSession(session: CK_SESSION_HANDLE) |c| {
    c.session(session)?; c.call("CloseSession", vec![Value::number(session as u64)])?;
    c.sessions.remove(&session); c.pending.retain(|(s, _), _| *s != session); Ok(())
});
function!(C_CloseAllSessions(slot: CK_SLOT_ID) |c| {
    c.call("CloseAllSessions", vec![Value::number(slot as u64)])?;
    c.sessions.retain(|_, s| *s != slot);
    c.pending.retain(|(s, _), _| c.sessions.contains_key(s)); Ok(())
});
function!(C_GetSessionInfo(session: CK_SESSION_HANDLE, p: CK_SESSION_INFO_PTR) |c| {
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?; let r = c.call("GetSessionInfo", vec![Value::number(session as u64)])?; let v = r.result(0)?;
    write(p, CK_SESSION_INFO { slotID: number(v, "SlotID")?, state: number(v, "State")?, flags: number(v, "Flags")?, ulDeviceError: number(v, "DeviceError")? })
});
function!(C_Login(session: CK_SESSION_HANDLE, user: CK_USER_TYPE, pin: CK_UTF8CHAR_PTR, n: CK_ULONG) |c| {
    c.session(session)?;
    // PINs come from the application's C_Login call, never the configuration file.
    c.call("Login", vec![Value::number(session as u64), Value::number(user as u64), Value::blob(bytes(pin, n)?)])?; Ok(())
});
function!(C_LoginUser(session: CK_SESSION_HANDLE, user: CK_USER_TYPE, pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG, username: CK_UTF8CHAR_PTR, username_len: CK_ULONG) |c| {
    c.session(session)?;
    let username = std::str::from_utf8(bytes(username, username_len)?)
        .map_err(|_| Error::rv(CKR_ARGUMENTS_BAD))?;
    c.call("LoginUser", vec![Value::number(session as u64), Value::number(user as u64),
        Value::blob(bytes(pin, pin_len)?), Value::string(username)])?; Ok(())
});

fn cancel(c: &mut Client, session: CK_SESSION_HANDLE, flags: CK_FLAGS) -> Result<()> {
    c.session(session)?;
    let allowed = CKF_FIND_OBJECTS | CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST | CKF_SIGN |
        CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_MESSAGE_ENCRYPT |
        CKF_MESSAGE_DECRYPT | CKF_MESSAGE_SIGN | CKF_MESSAGE_VERIFY;
    if flags & !allowed != 0 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if flags == 0 { return Ok(()); }
    c.call("SessionCancel", vec![Value::number(session as u64), Value::number(flags as u64)])?;
    // A size query may have finished the remote operation already. Discard its
    // cached result too, but keep results for other sessions and operation types.
    c.pending.retain(|(s, operation), _| {
        let flag = match *operation { "encrypt" => CKF_ENCRYPT, "decrypt" => CKF_DECRYPT,
            "digest" => CKF_DIGEST, "sign" => CKF_SIGN, _ => 0 };
        *s != session || flags & flag == 0
    });
    Ok(())
}
function!(C_SessionCancel(session: CK_SESSION_HANDLE, flags: CK_FLAGS) |c| { cancel(c, session, flags) });
function!(C_GetSessionValidationFlags(session: CK_SESSION_HANDLE, typ: CK_SESSION_VALIDATION_FLAGS_TYPE, out: CK_FLAGS_PTR) |c| {
    if out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?;
    let r = c.call("GetSessionValidationFlags", vec![Value::number(session as u64), Value::number(typ as u64)])?;
    // Report the HSM's flags, not an invented FIPS or validation claim.
    write(out, ulong(r.result(0)?.num()?)?)
});
function!(C_Logout(session: CK_SESSION_HANDLE) |c| {
    c.session(session)?; c.call("Logout", vec![Value::number(session as u64)])?;
    c.pending.clear(); Ok(())
});
function!(C_FindObjectsInit(session: CK_SESSION_HANDLE, p: CK_ATTRIBUTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; let attrs = attributes(p, n, c.ulong_size, false)?;
    c.call("FindObjectsInit", vec![Value::number(session as u64), attrs])?; Ok(())
});
function!(C_FindObjects(session: CK_SESSION_HANDLE, p: CK_OBJECT_HANDLE_PTR, maximum: CK_ULONG, n: CK_ULONG_PTR) |c| {
    c.session(session)?;
    if p.is_null() || n.is_null() || maximum == 0 || maximum > 4096 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let r = c.call("FindObjects", vec![Value::number(session as u64), Value::integer(maximum as i64)])?;
    let handles = r.result(0)?.list_ref()?.iter().map(|v| ulong(v.num()?)).collect::<Result<Vec<_>>>()?;
    if handles.len() > maximum as usize { return Err(Error::protocol()); }
    write(n, maximum)?; copy_output(&handles, p, n)
});
function!(C_FindObjectsFinal(session: CK_SESSION_HANDLE) |c| {
    c.session(session)?; c.call("FindObjectsFinal", vec![Value::number(session as u64)])?; Ok(())
});
function!(C_GetAttributeValue(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, p: CK_ATTRIBUTE_PTR, n: CK_ULONG) |c| {
    attribute_results(c, session, object, p, n)
});
function!(C_CreateObject(session: CK_SESSION_HANDLE, p: CK_ATTRIBUTE_PTR, n: CK_ULONG, out: CK_OBJECT_HANDLE_PTR) |c| {
    if out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?; let attrs = attributes(p, n, c.ulong_size, false)?;
    let r = c.call("CreateObject", vec![Value::number(session as u64), attrs])?;
    write(out, ulong(r.result(0)?.num()?)?)
});
function!(C_DestroyObject(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) |c| {
    c.session(session)?; c.call("DestroyObject", vec![Value::number(session as u64), Value::number(object as u64)])?; Ok(())
});
function!(C_GetObjectSize(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, out: CK_ULONG_PTR) |c| {
    if out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?; let r = c.call("GetObjectSize", vec![Value::number(session as u64), Value::number(object as u64)])?;
    write(out, ulong(r.result(0)?.num()?)?)
});
function!(C_SetAttributeValue(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, p: CK_ATTRIBUTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; let attrs = attributes(p, n, c.ulong_size, false)?;
    c.call("SetAttributeValue", vec![Value::number(session as u64), Value::number(object as u64), attrs])?; Ok(())
});

// The Go API returns a complete result. PKCS#11 callers normally ask for its size
// first, then supply a buffer. Keep that result so a size probe never signs twice.
unsafe fn output(c: &mut Client, session: CK_SESSION_HANDLE, operation: &'static str,
    method: &'static str, input: Option<&[u8]>, p: CK_BYTE_PTR, n: CK_ULONG_PTR) -> Result<()> {
    if n.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?;
    let key = (session, operation);
    if let Some(pending) = c.pending.get(&key) {
        if pending.method != method || pending.input.as_slice() != input.unwrap_or(&[]) {
            return Err(Error::rv(CKR_ARGUMENTS_BAD));
        }
    } else {
        let held: usize = c.pending.values().map(|p| p.input.len() + p.output.len()).sum();
        if held + 2 * MAX_DATA > 16 * MAX_DATA { return Err(Error::rv(CKR_HOST_MEMORY)); }
        let mut args = vec![Value::number(session as u64)];
        if let Some(input) = input { args.push(Value::blob(input)); }
        let r = c.call(method, args)?;
        let data = r.result(0)?.data()?;
        c.pending.insert(key, Pending { method, input: Zeroizing::new(input.unwrap_or(&[]).to_vec()), output: data });
    }
    let pending = c.pending.get(&key).ok_or(Error::protocol())?;
    let result = copy_output(pending.output.as_slice(), p, n);
    if result.is_ok() && !p.is_null() { c.pending.remove(&key); }
    result
}
macro_rules! crypto {
    ($init:ident, $one:ident, $update:ident, $final:ident, $operation:literal, $flag:ident,
     $remote_init:literal, $remote_one:literal, $remote_update:literal, $remote_final:literal) => {
        function!($init(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE) |c| {
            if m.is_null() { return cancel(c, session, $flag); }
            c.ready(session, $operation)?; let mechanism = mechanism(m)?;
            c.call($remote_init, vec![Value::number(session as u64), mechanism, Value::number(key as u64)])?; Ok(())
        });
        function!($one(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, len: CK_ULONG, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
            output(c, session, $operation, $remote_one, Some(bytes(input, len)?), p, n)
        });
        function!($update(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, len: CK_ULONG, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
            output(c, session, $operation, $remote_update, Some(bytes(input, len)?), p, n)
        });
        function!($final(session: CK_SESSION_HANDLE, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
            output(c, session, $operation, $remote_final, None, p, n)
        });
    };
}
crypto!(C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal, "encrypt", CKF_ENCRYPT, "EncryptInit", "Encrypt", "EncryptUpdate", "EncryptFinal");
crypto!(C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal, "decrypt", CKF_DECRYPT, "DecryptInit", "Decrypt", "DecryptUpdate", "DecryptFinal");

function!(C_SignInit(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE) |c| {
    if m.is_null() { return cancel(c, session, CKF_SIGN); }
    c.ready(session, "sign")?; let m = mechanism(m)?;
    c.call("SignInit", vec![Value::number(session as u64), m, Value::number(key as u64)])?; Ok(())
});
function!(C_Sign(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, len: CK_ULONG, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
    output(c, session, "sign", "Sign", Some(bytes(input, len)?), p, n)
});
function!(C_SignUpdate(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.ready(session, "sign")?; c.call("SignUpdate", vec![Value::number(session as u64), Value::blob(bytes(input, n)?)])?; Ok(())
});
function!(C_SignFinal(session: CK_SESSION_HANDLE, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
    output(c, session, "sign", "SignFinal", None, p, n)
});
function!(C_VerifyInit(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE) |c| {
    if m.is_null() { return cancel(c, session, CKF_VERIFY); }
    c.session(session)?; let m = mechanism(m)?;
    c.call("VerifyInit", vec![Value::number(session as u64), m, Value::number(key as u64)])?; Ok(())
});
function!(C_Verify(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, len: CK_ULONG, signature: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; c.call("Verify", vec![Value::number(session as u64), Value::blob(bytes(input, len)?), Value::blob(bytes(signature, n)?)])?; Ok(())
});
function!(C_VerifyUpdate(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; c.call("VerifyUpdate", vec![Value::number(session as u64), Value::blob(bytes(input, n)?)])?; Ok(())
});
function!(C_VerifyFinal(session: CK_SESSION_HANDLE, signature: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; c.call("VerifyFinal", vec![Value::number(session as u64), Value::blob(bytes(signature, n)?)])?; Ok(())
});
// Signature-first verification has its own broker operations. Do not silently
// turn it into classic Verify: the HSM decides whether it supports this flow.
function!(C_VerifySignatureInit(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, key: CK_OBJECT_HANDLE,
    signature: CK_BYTE_PTR, n: CK_ULONG) |c| {
    if m.is_null() { return cancel(c, session, CKF_VERIFY); }
    c.session(session)?; let m = mechanism(m)?;
    c.call("VerifySignatureInit", vec![Value::number(session as u64), m,
        Value::number(key as u64), Value::blob(bytes(signature, n)?)])?; Ok(())
});
function!(C_VerifySignature(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?;
    c.call("VerifySignature", vec![Value::number(session as u64), Value::blob(bytes(data, n)?)])?; Ok(())
});
function!(C_VerifySignatureUpdate(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?;
    c.call("VerifySignatureUpdate", vec![Value::number(session as u64), Value::blob(bytes(data, n)?)])?; Ok(())
});
function!(C_VerifySignatureFinal(session: CK_SESSION_HANDLE) |c| {
    c.session(session)?; c.call("VerifySignatureFinal", vec![Value::number(session as u64)])?; Ok(())
});
function!(C_DigestInit(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR) |c| {
    if m.is_null() { return cancel(c, session, CKF_DIGEST); }
    c.ready(session, "digest")?; let m = mechanism(m)?;
    c.call("DigestInit", vec![Value::number(session as u64), m])?; Ok(())
});
function!(C_Digest(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, len: CK_ULONG, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
    output(c, session, "digest", "Digest", Some(bytes(input, len)?), p, n)
});
function!(C_DigestUpdate(session: CK_SESSION_HANDLE, input: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.ready(session, "digest")?; c.call("DigestUpdate", vec![Value::number(session as u64), Value::blob(bytes(input, n)?)])?; Ok(())
});
function!(C_DigestKey(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) |c| {
    c.ready(session, "digest")?; c.call("DigestKey", vec![Value::number(session as u64), Value::number(key as u64)])?; Ok(())
});
function!(C_DigestFinal(session: CK_SESSION_HANDLE, p: CK_BYTE_PTR, n: CK_ULONG_PTR) |c| {
    output(c, session, "digest", "DigestFinal", None, p, n)
});
function!(C_GenerateKey(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, attrs: CK_ATTRIBUTE_PTR, n: CK_ULONG, out: CK_OBJECT_HANDLE_PTR) |c| {
    if out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?; let m = mechanism(m)?; let attrs = attributes(attrs, n, c.ulong_size, false)?;
    let r = c.call("GenerateKey", vec![Value::number(session as u64), m, attrs])?;
    write(out, ulong(r.result(0)?.num()?)?)
});
function!(C_GenerateKeyPair(session: CK_SESSION_HANDLE, m: CK_MECHANISM_PTR, public: CK_ATTRIBUTE_PTR, public_n: CK_ULONG, private: CK_ATTRIBUTE_PTR, private_n: CK_ULONG, public_out: CK_OBJECT_HANDLE_PTR, private_out: CK_OBJECT_HANDLE_PTR) |c| {
    if public_out.is_null() || private_out.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    c.session(session)?; let m = mechanism(m)?;
    let public = attributes(public, public_n, c.ulong_size, false)?; let private = attributes(private, private_n, c.ulong_size, false)?;
    let r = c.call("GenerateKeyPair", vec![Value::number(session as u64), m, public, private])?;
    let (public, private) = (ulong(r.result(0)?.num()?)?, ulong(r.result(1)?.num()?)?);
    write(public_out, public)?; write(private_out, private)
});
function!(C_GenerateRandom(session: CK_SESSION_HANDLE, p: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; let size = count(n)?;
    if p.is_null() && size != 0 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if size == 0 { return Ok(()); }
    let r = c.call("GenerateRandom", vec![Value::number(session as u64), Value::integer(size as i64)])?;
    let data = r.result(0)?.data()?;
    if data.len() != size { return Err(Error::protocol()); }
    ptr::copy_nonoverlapping(data.as_ptr(), p, size); Ok(())
});
function!(C_SeedRandom(session: CK_SESSION_HANDLE, p: CK_BYTE_PTR, n: CK_ULONG) |c| {
    c.session(session)?; c.call("SeedRandom", vec![Value::number(session as u64), Value::blob(bytes(p, n)?)])?; Ok(())
});

include!("functions.rs");
