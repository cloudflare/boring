#![forbid(unsafe_op_in_unsafe_fn)]

use crate::ffi;
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

use crate::error::ErrorStack;
use crate::ssl::AlpnError;
use crate::ssl::{ClientHello, SelectCertError};
use crate::ssl::{
    SniError, Ssl, SslAlert, SslContext, SslContextRef, SslRef, SslSession, SslSessionRef,
    SESSION_CTX_INDEX,
};
use crate::x509::{X509StoreContext, X509StoreContextRef};

pub(super) unsafe extern "C" fn raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let ssl_idx = X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
    let verify_idx = SslContext::cached_ex_index::<F>();

    let verify = ctx
        .ex_data(ssl_idx)
        .expect("BUG: store context missing ssl")
        .ssl_context()
        .ex_data(verify_idx)
        .expect("BUG: verify callback missing");

    // SAFETY: The callback won't outlive the context it's associated with
    // because there is no `X509StoreContextRef::ssl_mut(&mut self)` method.
    let verify = unsafe { &*(verify as *const F) };

    verify(preverify_ok != 0, ctx) as c_int
}

pub(super) unsafe extern "C" fn raw_client_psk<F>(
    ssl_ptr: *mut ffi::SSL,
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
    // SAFETY: boring provides valid inputs.

    let ssl = unsafe { SslRef::from_ptr_mut(ssl_ptr) };

    let hint = if hint.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(hint) }.to_bytes())
    };

    // Give the callback mutable slices into which it can write the identity and psk.
    let identity_sl =
        unsafe { slice::from_raw_parts_mut(identity as *mut u8, max_identity_len as usize) };
    let psk_sl = unsafe { slice::from_raw_parts_mut(psk, max_psk_len as usize) };

    let ssl_context = ssl.ssl_context().to_owned();
    let callback = ssl_context
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: psk callback missing");

    match callback(ssl, hint, identity_sl, psk_sl) {
        Ok(psk_len) => psk_len as u32,
        Err(e) => {
            e.put();
            0
        }
    }
}

pub(super) unsafe extern "C" fn raw_server_psk<F>(
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
    // SAFETY: boring provides valid inputs.

    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let identity = if identity.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(identity) }.to_bytes())
    };

    // Give the callback mutable slices into which it can write the psk.
    let psk_sl = unsafe { slice::from_raw_parts_mut(psk, max_psk_len as usize) };

    let ssl_context = ssl.ssl_context().to_owned();
    let callback = ssl_context
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: psk callback missing");

    match callback(ssl, identity, psk_sl) {
        Ok(psk_len) => psk_len as u32,
        Err(e) => {
            e.put();
            0
        }
    }
}

pub(super) unsafe extern "C" fn ssl_raw_verify<F>(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int
where
    F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let ssl_idx = X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");

    // NOTE(nox): I'm pretty sure this Arc<F> is unnecessary here as there is
    // no way to get a `&mut SslRef` from a `&mut X509StoreContextRef`, and I
    // don't understand how this callback is different from `raw_verify` above.
    let callback = ctx
        .ex_data(ssl_idx)
        .expect("BUG: store context missing ssl")
        .ex_data(Ssl::cached_ex_index::<Arc<F>>())
        .expect("BUG: ssl verify callback missing")
        .clone();

    callback(preverify_ok != 0, ctx) as c_int
}

pub(super) unsafe extern "C" fn raw_sni<F>(
    ssl: *mut ffi::SSL,
    al: *mut c_int,
    arg: *mut c_void,
) -> c_int
where
    F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let al = unsafe { &mut *al };

    // SAFETY: We can make `callback` outlive `ssl` because it is a callback
    // stored in the original context with which `ssl` was built. That
    // original context is always stored as the session context in
    // `Ssl::new` so it is always guaranteed to outlive the lifetime of
    // this function's scope.
    let callback = unsafe { &*(arg as *const F) };

    let mut alert = SslAlert(*al);

    let r = callback(ssl, &mut alert);

    *al = alert.0;

    match r {
        Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
        Err(e) => e.0,
    }
}

pub(super) unsafe extern "C" fn raw_alpn_select<F>(
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
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let protos = unsafe { slice::from_raw_parts(inbuf, inlen as usize) };
    let out = unsafe { &mut *out };
    let outlen = unsafe { &mut *outlen };

    let ssl_context = ssl.ssl_context().to_owned();
    let callback = ssl_context
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: alpn callback missing");

    match callback(ssl, protos) {
        Ok(proto) => {
            *out = proto.as_ptr() as *const c_uchar;
            *outlen = proto.len() as c_uchar;

            ffi::SSL_TLSEXT_ERR_OK
        }
        Err(e) => e.0,
    }
}

pub(super) unsafe extern "C" fn raw_select_cert<F>(
    client_hello: *const ffi::SSL_CLIENT_HELLO,
) -> ffi::ssl_select_cert_result_t
where
    F: Fn(&ClientHello) -> Result<(), SelectCertError> + Sync + Send + 'static,
{
    // SAFETY: boring provides valid inputs.
    let client_hello = unsafe { &*(client_hello as *const ClientHello) };

    let callback = client_hello
        .ssl()
        .ssl_context()
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: select cert callback missing");

    match callback(client_hello) {
        Ok(()) => ffi::ssl_select_cert_result_t::ssl_select_cert_success,
        Err(e) => e.0,
    }
}

pub(super) unsafe extern "C" fn raw_tlsext_status<F>(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int
where
    F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let ssl_context = ssl.ssl_context().to_owned();
    let callback = ssl_context
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: ocsp callback missing");

    let ret = callback(ssl);

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

pub(super) unsafe extern "C" fn raw_new_session<F>(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int
where
    F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let session = unsafe { SslSession::from_ptr(session) };

    let callback = ssl
        .ex_data(*SESSION_CTX_INDEX)
        .expect("BUG: session context missing")
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: new session callback missing");

    // SAFETY: We can make `callback` outlive `ssl` because it is a callback
    // stored in the session context set in `Ssl::new` so it is always
    // guaranteed to outlive the lifetime of this function's scope.
    let callback = unsafe { &*(callback as *const F) };

    callback(ssl, session);

    // the return code doesn't indicate error vs success, but whether or not we consumed the session
    1
}

pub(super) unsafe extern "C" fn raw_remove_session<F>(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) where
    F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { SslContextRef::from_ptr(ctx) };
    let session = unsafe { SslSessionRef::from_ptr(session) };

    let callback = ctx
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: remove session callback missing");

    callback(ctx, session)
}

type DataPtr = *const c_uchar;

pub(super) unsafe extern "C" fn raw_get_session<F>(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION
where
    F: Fn(&mut SslRef, &[u8]) -> Option<SslSession> + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let data = unsafe { slice::from_raw_parts(data, len as usize) };
    let copy = unsafe { &mut *copy };

    let callback = ssl
        .ex_data(*SESSION_CTX_INDEX)
        .expect("BUG: session context missing")
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: get session callback missing");

    // SAFETY: We can make `callback` outlive `ssl` because it is a callback
    // stored in the session context set in `Ssl::new` so it is always
    // guaranteed to outlive the lifetime of this function's scope.
    let callback = unsafe { &*(callback as *const F) };

    match callback(ssl, data) {
        Some(session) => {
            let p = session.as_ptr();
            mem::forget(session);
            *copy = 0;
            p
        }
        None => ptr::null_mut(),
    }
}

pub(super) unsafe extern "C" fn raw_keylog<F>(ssl: *const ffi::SSL, line: *const c_char)
where
    F: Fn(&SslRef, &str) + 'static + Sync + Send,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr(ssl as *mut _) };
    let line = unsafe { str::from_utf8_unchecked(CStr::from_ptr(line).to_bytes()) };

    let callback = ssl
        .ssl_context()
        .ex_data(SslContext::cached_ex_index::<F>())
        .expect("BUG: get session callback missing");

    callback(ssl, line);
}
