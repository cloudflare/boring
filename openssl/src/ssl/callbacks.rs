use ffi;
use foreign_types::ForeignType;
use foreign_types::ForeignTypeRef;
use libc::c_char;
use libc::{c_int, c_uchar, c_uint, c_void};
use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;

use error::ErrorStack;
#[cfg(any(ossl102, libressl261))]
use ssl::AlpnError;
use ssl::{
    SniError, Ssl, SslAlert, SslContext, SslContextRef, SslRef, SslSession, SslSessionRef,
    SESSION_CTX_INDEX,
};
use x509::{X509StoreContext, X509StoreContextRef};

pub extern "C" fn raw_verify<F>(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unsafe {
        let ctx = X509StoreContextRef::from_ptr_mut(x509_ctx);
        let ssl_idx = X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
        let verify_idx = SslContext::cached_ex_index::<F>();

        // raw pointer shenanigans to break the borrow of ctx
        // the callback can't mess with its own ex_data slot so this is safe
        let verify = ctx
            .ex_data(ssl_idx)
            .expect("BUG: store context missing ssl")
            .ssl_context()
            .ex_data(verify_idx)
            .expect("BUG: verify callback missing") as *const F;

        (*verify)(preverify_ok != 0, ctx) as c_int
    }
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
pub extern "C" fn raw_client_psk<F>(
    ssl: *mut ffi::SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    unsafe {
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback_idx = SslContext::cached_ex_index::<F>();

        let callback = ssl
            .ssl_context()
            .ex_data(callback_idx)
            .expect("BUG: psk callback missing") as *const F;
        let hint = if !hint.is_null() {
            Some(CStr::from_ptr(hint).to_bytes())
        } else {
            None
        };
        // Give the callback mutable slices into which it can write the identity and psk.
        let identity_sl = slice::from_raw_parts_mut(identity as *mut u8, max_identity_len as usize);
        let psk_sl = slice::from_raw_parts_mut(psk as *mut u8, max_psk_len as usize);
        match (*callback)(ssl, hint, identity_sl, psk_sl) {
            Ok(psk_len) => psk_len as u32,
            Err(e) => {
                e.put();
                0
            }
        }
    }
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
pub extern "C" fn raw_server_psk<F>(
    ssl: *mut ffi::SSL,
    identity: *const c_char,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint
where
    F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack>
        + 'static
        + Sync
        + Send,
{
    unsafe {
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback_idx = SslContext::cached_ex_index::<F>();

        let callback = ssl
            .ssl_context()
            .ex_data(callback_idx)
            .expect("BUG: psk callback missing") as *const F;
        let identity = if identity.is_null() {
            None
        } else {
            Some(CStr::from_ptr(identity).to_bytes())
        };
        // Give the callback mutable slices into which it can write the psk.
        let psk_sl = slice::from_raw_parts_mut(psk as *mut u8, max_psk_len as usize);
        match (*callback)(ssl, identity, psk_sl) {
            Ok(psk_len) => psk_len as u32,
            Err(e) => {
                e.put();
                0
            }
        }
    }
}

pub extern "C" fn ssl_raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    unsafe {
        let ctx = X509StoreContextRef::from_ptr_mut(x509_ctx);
        let ssl_idx = X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
        let callback_idx = Ssl::cached_ex_index::<Arc<F>>();

        let callback = ctx
            .ex_data(ssl_idx)
            .expect("BUG: store context missing ssl")
            .ex_data(callback_idx)
            .expect("BUG: ssl verify callback missing")
            .clone();

        callback(preverify_ok != 0, ctx) as c_int
    }
}

pub extern "C" fn raw_sni<F>(ssl: *mut ffi::SSL, al: *mut c_int, arg: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
{
    unsafe {
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = arg as *const F;
        let mut alert = SslAlert(*al);

        let r = (*callback)(ssl, &mut alert);
        *al = alert.0;
        match r {
            Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
            Err(e) => e.0,
        }
    }
}

#[cfg(any(ossl102, libressl261))]
pub extern "C" fn raw_alpn_select<F>(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int
where
    F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
{
    unsafe {
        let ssl = SslRef::from_ptr_mut(ssl);
        let callback = ssl
            .ssl_context()
            .ex_data(SslContext::cached_ex_index::<F>())
            .expect("BUG: alpn callback missing") as *const F;
        let protos = slice::from_raw_parts(inbuf as *const u8, inlen as usize);

        match (*callback)(ssl, protos) {
            Ok(proto) => {
                *out = proto.as_ptr() as *const c_uchar;
                *outlen = proto.len() as c_uchar;
                ffi::SSL_TLSEXT_ERR_OK
            }
            Err(e) => e.0,
        }
    }
}

pub unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
{
    let ssl = SslRef::from_ptr_mut(ssl);
    let callback = ssl
        .ssl_context()
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: ocsp callback missing") as *const F;
    let ret = (*callback)(ssl);

    if ssl.is_server() {
        match ret {
            Ok(true) => ffi::SSL_TLSEXT_ERR_OK,
            Ok(false) => ffi::SSL_TLSEXT_ERR_NOACK,
            Err(e) => {
                e.put();
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    } else {
        match ret {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => {
                e.put();
                -1
            }
        }
    }
}

pub unsafe extern "C" fn raw_new_session<F>(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int
where
    F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
{
    let ssl = SslRef::from_ptr_mut(ssl);
    let callback = ssl
        .ex_data(*SESSION_CTX_INDEX)
        .expect("BUG: session context missing")
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: new session callback missing") as *const F;
    let session = SslSession::from_ptr(session);

    (*callback)(ssl, session);

    // the return code doesn't indicate error vs success, but whether or not we consumed the session
    1
}

pub unsafe extern "C" fn raw_remove_session<F>(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) where
    F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
{
    let ctx = SslContextRef::from_ptr(ctx);
    let callback = ctx
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: remove session callback missing");
    let session = SslSessionRef::from_ptr(session);

    callback(ctx, session)
}

cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        type DataPtr = *const c_uchar;
    } else {
        type DataPtr = *mut c_uchar;
    }
}

pub unsafe extern "C" fn raw_get_session<F>(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION
where
    F: Fn(&mut SslRef, &[u8]) -> Option<SslSession> + 'static + Sync + Send,
{
    let ssl = SslRef::from_ptr_mut(ssl);
    let callback = ssl
        .ex_data(*SESSION_CTX_INDEX)
        .expect("BUG: session context missing")
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: get session callback missing") as *const F;
    let data = slice::from_raw_parts(data as *const u8, len as usize);

    match (*callback)(ssl, data) {
        Some(session) => {
            let p = session.as_ptr();
            mem::forget(session);
            *copy = 0;
            p
        }
        None => ptr::null_mut(),
    }
}

pub unsafe extern "C" fn raw_keylog<F>(ssl: *const ffi::SSL, line: *const c_char)
where
    F: Fn(&SslRef, &str) + 'static + Sync + Send,
{
    let ssl = SslRef::from_ptr(ssl as *mut _);
    let callback = ssl
        .ssl_context()
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: get session callback missing");
    let line = CStr::from_ptr(line).to_bytes();
    let line = str::from_utf8_unchecked(line);

    callback(ssl, line);
}
