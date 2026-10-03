//! The ABI boundary. Pointers only live here and in the exported entry points.
//! Network messages contain values, never addresses from the calling application.
use crate::{wire::{Client, Value, MAX_DATA}, Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use cryptoki_sys::*;
use serde_json::json;
use std::{mem::size_of, ptr, slice};
use zeroize::Zeroizing;

pub fn ulong(n: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(n).map_err(|_| Error::protocol())
}
pub fn count(n: CK_ULONG) -> Result<usize> {
    let n = usize::try_from(n).map_err(|_| Error::rv(CKR_ARGUMENTS_BAD))?;
    if n > MAX_DATA { Err(Error::rv(CKR_DATA_LEN_RANGE)) } else { Ok(n) }
}
pub unsafe fn read<T: Copy>(p: *const T) -> Result<T> {
    if p.is_null() { Err(Error::rv(CKR_ARGUMENTS_BAD)) } else { Ok(ptr::read_unaligned(p)) }
}
pub unsafe fn write<T>(p: *mut T, v: T) -> Result<()> {
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    ptr::write_unaligned(p, v); Ok(())
}
pub unsafe fn bytes<'a>(p: *const u8, n: CK_ULONG) -> Result<&'a [u8]> {
    let n = count(n)?;
    if n == 0 { return Ok(&[]); }
    if p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    Ok(slice::from_raw_parts(p, n))
}
pub unsafe fn copy_output<T: Copy>(values: &[T], output: *mut T, length: *mut CK_ULONG) -> Result<()> {
    if length.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let capacity = if output.is_null() { 0 } else { read(length)? as usize };
    write(length, ulong(values.len() as u64)?)?;
    if output.is_null() { return Ok(()); }
    if capacity < values.len() { return Err(Error::rv(CKR_BUFFER_TOO_SMALL)); }
    if !values.is_empty() { ptr::copy_nonoverlapping(values.as_ptr(), output, values.len()); }
    Ok(())
}
pub fn padded<const N: usize>(text: &str) -> [u8; N] {
    let mut result = [b' '; N];
    let n = text.len().min(N); result[..n].copy_from_slice(&text.as_bytes()[..n]); result
}
pub fn version(value: &Value) -> Result<CK_VERSION> {
    Ok(CK_VERSION {
        major: u8::try_from(value.field("Major")?.num()?).map_err(|_| Error::protocol())?,
        minor: u8::try_from(value.field("Minor")?.num()?).map_err(|_| Error::protocol())?,
    })
}
pub fn number(value: &Value, field: &str) -> Result<CK_ULONG> { ulong(value.field(field)?.num()?) }
pub fn available(value: &Value, field: &str, width: usize) -> Result<CK_ULONG> {
    let n = value.field(field)?.num()?;
    if n == u64::MAX || (width == 4 && n == u32::MAX as u64) { Ok(CK_ULONG::MAX) } else { ulong(n) }
}

// Integer attributes are stored as native CK_ULONG bytes by raw.Attribute.
// Big integers such as RSA moduli are NOT CK_ULONGs and must not be byte-swapped.
fn scalar_attribute(typ: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(typ, CKA_CLASS | CKA_CERTIFICATE_TYPE | CKA_CERTIFICATE_CATEGORY |
        CKA_JAVA_MIDP_SECURITY_DOMAIN | CKA_NAME_HASH_ALGORITHM | CKA_KEY_TYPE |
        CKA_MODULUS_BITS | CKA_PRIME_BITS | CKA_SUBPRIME_BITS | CKA_VALUE_BITS |
        CKA_VALUE_LEN | CKA_KEY_GEN_MECHANISM | CKA_MECHANISM_TYPE)
}
fn nested_attribute(typ: CK_ATTRIBUTE_TYPE) -> bool {
    typ & CKF_ARRAY_ATTRIBUTE != 0 && typ != CKA_ALLOWED_MECHANISMS
}
fn convert_integers(value: &[u8], from: usize, to: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !matches!(from, 4 | 8) || !matches!(to, 4 | 8) || value.len() % from != 0 {
        return Err(Error::rv(CKR_ATTRIBUTE_VALUE_INVALID));
    }
    let mut result = Zeroizing::new(Vec::with_capacity(value.len() / from * to));
    for chunk in value.chunks_exact(from) {
        let mut raw = [0u8;8]; raw[..from].copy_from_slice(chunk);
        let mut value = u64::from_le_bytes(raw);
        if from == 4 && value == u32::MAX as u64 { value = u64::MAX; }
        if to == 4 && value > u32::MAX as u64 && value != u64::MAX { return Err(Error::protocol()); }
        result.extend_from_slice(&value.to_le_bytes()[..to]);
    }
    Ok(result)
}
pub unsafe fn attributes(p: CK_ATTRIBUTE_PTR, n: CK_ULONG, width: usize, query: bool) -> Result<Value> {
    let n = count(n)?;
    if n > 256 { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    if n > 0 && p.is_null() { return Err(Error::rv(CKR_ARGUMENTS_BAD)); }
    let mut result = Vec::with_capacity(n);
    let mut total = 0usize;
    for i in 0..n {
        let a = read(p.add(i))?;
        if nested_attribute(a.type_) { return Err(Error::rv(CKR_ATTRIBUTE_TYPE_INVALID)); }
        let value = if query { Value::nil() } else {
            let data = bytes(a.pValue.cast(), a.ulValueLen)?;
            total += data.len();
            if total > MAX_DATA { return Err(Error::rv(CKR_DATA_LEN_RANGE)); }
            if scalar_attribute(a.type_) || a.type_ == CKA_ALLOWED_MECHANISMS {
                if scalar_attribute(a.type_) && data.len() != size_of::<CK_ULONG>() { return Err(Error::rv(CKR_ATTRIBUTE_VALUE_INVALID)); }
                let data = convert_integers(data, size_of::<CK_ULONG>(), width)?;
                Value::blob(&data)
            } else { Value::blob(data) }
        };
        result.push(Value::structure(vec![("Type", Value::number(a.type_ as u64)), ("Value", value), ("Children", Value::nil())]));
    }
    Ok(Value::list(result))
}
pub unsafe fn attribute_results(client: &mut Client, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, p: CK_ATTRIBUTE_PTR, n: CK_ULONG) -> Result<()> {
    client.session(session)?;
    let query = attributes(p, n, client.ulong_size, true)?;
    let reply = client.request("GetAttributeValue", vec![Value::number(session as u64), Value::number(object as u64), query])?;
    let mut rv = reply.rv();
    if !matches!(rv, CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL) { return Err(Error::rv(rv)); }
    let values = reply.result(0)?.list_ref()?;
    if values.len() != n as usize { return Err(Error::protocol()); }
    for (i, value) in values.iter().enumerate() {
        let mut a = read(p.add(i))?;
        if number(value, "Type")? != a.type_ { return Err(Error::protocol()); }
        let value = value.field("Value")?;
        if value.kind == 1 {
            a.ulValueLen = CK_ULONG::MAX;
            if rv == CKR_OK { rv = CKR_ATTRIBUTE_TYPE_INVALID; }
        } else {
            let mut data = value.data()?;
            if scalar_attribute(a.type_) || a.type_ == CKA_ALLOWED_MECHANISMS {
                if scalar_attribute(a.type_) && data.len() != client.ulong_size { return Err(Error::protocol()); }
                data = convert_integers(&data, client.ulong_size, size_of::<CK_ULONG>())?;
            }
            let capacity = a.ulValueLen as usize;
            a.ulValueLen = ulong(data.len() as u64)?;
            if !a.pValue.is_null() {
                if capacity < data.len() {
                    if rv == CKR_OK { rv = CKR_BUFFER_TOO_SMALL; }
                } else if !data.is_empty() { ptr::copy_nonoverlapping(data.as_ptr(), a.pValue.cast(), data.len()); }
            }
        }
        write(p.add(i), a)?;
    }
    if rv == CKR_OK { Ok(()) } else { Err(Error::rv(rv)) }
}

pub fn supported_mechanism(m: CK_MECHANISM_TYPE) -> bool {
    matches!(m, CKM_RSA_PKCS_KEY_PAIR_GEN | CKM_RSA_PKCS | CKM_RSA_X_509 |
        CKM_SHA1_RSA_PKCS | CKM_SHA224_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS |
        CKM_RSA_PKCS_PSS | CKM_SHA1_RSA_PKCS_PSS | CKM_SHA224_RSA_PKCS_PSS | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS |
        CKM_RSA_PKCS_OAEP | CKM_EC_KEY_PAIR_GEN | CKM_ECDSA | CKM_ECDSA_SHA1 |
        CKM_ECDSA_SHA224 | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 | CKM_EDDSA |
        CKM_SHA_1 | CKM_SHA224 | CKM_SHA256 | CKM_SHA384 | CKM_SHA512 |
        CKM_SHA_1_HMAC | CKM_SHA224_HMAC | CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC |
        CKM_GENERIC_SECRET_KEY_GEN | CKM_AES_KEY_GEN | CKM_AES_ECB | CKM_AES_CBC | CKM_AES_CBC_PAD | CKM_AES_CTR | CKM_AES_GCM)
}
unsafe fn parameter<T: Copy>(m: &CK_MECHANISM) -> Result<T> {
    if m.ulParameterLen as usize != size_of::<T>() || m.pParameter.is_null() { return Err(Error::rv(CKR_MECHANISM_PARAM_INVALID)); }
    read(m.pParameter.cast())
}
fn json_parameter(kind: &str, value: serde_json::Value) -> Result<Value> {
    Ok(Value::param(kind, Some(serde_json::to_vec(&value).map_err(|_| Error::protocol())?)))
}
pub unsafe fn mechanism(p: CK_MECHANISM_PTR) -> Result<Value> {
    let m = read(p)?;
    if !supported_mechanism(m.mechanism) { return Err(Error::rv(CKR_MECHANISM_INVALID)); }
    let v = match m.mechanism {
        CKM_RSA_PKCS_PSS | CKM_SHA1_RSA_PKCS_PSS | CKM_SHA224_RSA_PKCS_PSS | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS => {
            let p: CK_RSA_PKCS_PSS_PARAMS = parameter(&m)?;
            let (hash, mgf, salt) = (p.hashAlg, p.mgf, p.sLen);
            json_parameter("pkcs11:pss", json!({"HashAlg": hash, "MGF": mgf, "SaltLen": salt}))?
        }
        CKM_RSA_PKCS_OAEP => {
            let p: CK_RSA_PKCS_OAEP_PARAMS = parameter(&m)?;
            let (hash, mgf, source) = (p.hashAlg, p.mgf, p.source);
            json_parameter("pkcs11:oaep", json!({"HashAlg": hash, "MGF": mgf, "Source": source,
                "SourceData": STANDARD.encode(bytes(p.pSourceData.cast(), p.ulSourceDataLen)?)}))?
        }
        CKM_AES_CTR => {
            let p: CK_AES_CTR_PARAMS = parameter(&m)?;
            let (bits, counter) = (p.ulCounterBits, p.cb);
            json_parameter("pkcs11:aes-ctr", json!({"CounterBits": bits, "Counter": counter}))?
        }
        CKM_AES_GCM => {
            let p: CK_GCM_PARAMS = parameter(&m)?;
            let (bits, tag) = (p.ulIvBits, p.ulTagBits);
            json_parameter("pkcs11:gcm", json!({"IV": STANDARD.encode(bytes(p.pIv, p.ulIvLen)?),
                "IVBits": bits, "AAD": STANDARD.encode(bytes(p.pAAD, p.ulAADLen)?), "TagBits": tag}))?
        }
        CKM_AES_CBC | CKM_AES_CBC_PAD => {
            if m.ulParameterLen != 16 { return Err(Error::rv(CKR_MECHANISM_PARAM_INVALID)); }
            Value::param("bytes", Some(bytes(m.pParameter.cast(), m.ulParameterLen)?.to_vec()))
        }
        _ => {
            // Pure EdDSA is supported. Context and prehash variants need a separate codec.
            if m.ulParameterLen != 0 { return Err(Error::rv(CKR_MECHANISM_PARAM_INVALID)); }
            Value::param("nil", None)
        }
    };
    Ok(Value::list(vec![Value::structure(vec![("Mechanism", Value::number(m.mechanism as u64)), ("Parameter", v)])]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_and_unix_attributes() {
        assert_eq!(&*convert_integers(&2u32.to_le_bytes(), 4, 8).unwrap(), &2u64.to_le_bytes());
        assert_eq!(&*convert_integers(&2u64.to_le_bytes(), 8, 4).unwrap(), &2u32.to_le_bytes());
        assert_eq!(&*convert_integers(&u32::MAX.to_le_bytes(), 4, 8).unwrap(), &u64::MAX.to_le_bytes());
        assert_eq!(&*convert_integers(&u64::MAX.to_le_bytes(), 8, 4).unwrap(), &u32::MAX.to_le_bytes());
        assert!(convert_integers(&(1u64 << 40).to_le_bytes(), 8, 4).is_err());
        assert!(!scalar_attribute(CKA_MODULUS));
        assert!(!scalar_attribute(CKA_PUBLIC_EXPONENT));
        assert!(scalar_attribute(CKA_MODULUS_BITS));
    }
    #[test]
    fn short_buffers_do_not_get_written() {
        unsafe {
            let mut out = [77u8;2]; let mut n = 2;
            assert_eq!(copy_output(&[1u8,2,3], out.as_mut_ptr(), &mut n).unwrap_err().rv, CKR_BUFFER_TOO_SMALL);
            assert_eq!(n, 3); assert_eq!(out, [77,77]);
            copy_output::<u8>(&[1,2,3], ptr::null_mut(), &mut n).unwrap();
            assert_eq!(n, 3);
        }
    }
}
