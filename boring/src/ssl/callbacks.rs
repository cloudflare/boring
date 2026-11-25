#![forbid(unsafe_op_in_unsafe_fn)]

use super::{
    AlpnError, CertificateCompressor, ClientHello, GetSessionPendingError, PrivateKeyMethod,
    PrivateKeyMethodError, SelectCertAction, SelectCertError, SniError, SslAlert, SslContextRef,
    SslInfoCallbackAlert, SslInfoCallbackMode, SslInfoCallbackValue, SslRef, SslSession,
    SslSessionRef, SslSignatureAlgorithm, SslVerifyError,
};
use crate::error::ErrorStack;
use crate::ffi;
use crate::hmac::HmacCtxRef;
use crate::ssl::TicketKeyCallbackResult;
use crate::symm::CipherCtxRef;
use crate::x509::X509StoreContextRef;
use foreign_types::ForeignType;
use foreign_types::ForeignTypeRef;
use libc::{c_char, c_int, c_uchar, c_uint, c_void};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt;
use std::io::Write;
use std::mem::{self, MaybeUninit};
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;

pub(crate) type CertVerifyCallback = dyn Fn(&mut X509StoreContextRef) -> bool + Send + Sync;
pub(crate) type VerifyCallback = dyn Fn(bool, &mut X509StoreContextRef) -> bool + Send + Sync;
pub(crate) type CustomVerifyCallback =
    dyn Fn(&mut SslRef) -> Result<(), SslVerifyError> + Send + Sync;
pub(crate) type ServernameCallback =
    dyn Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + Send + Sync;
pub(crate) type TicketKeyCallback = dyn Fn(
        &SslRef,
        &mut [u8; 16],
        &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
        &mut CipherCtxRef,
        &mut HmacCtxRef,
        bool,
    ) -> TicketKeyCallbackResult
    + Send
    + Sync;
pub(crate) type AlpnSelectCallback =
    dyn for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + Send + Sync;
pub(crate) type SelectCertificateCallback =
    dyn for<'a> Fn(ClientHello<'a>) -> Result<SelectCertAction, SelectCertError> + Send + Sync;
pub(crate) type StatusCallback = dyn Fn(&mut SslRef) -> Result<bool, ErrorStack> + Send + Sync;
pub(crate) type PskClientCallback = dyn Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
    + Send
    + Sync;
pub(crate) type PskServerCallback =
    dyn Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack> + Send + Sync;
pub(crate) type NewSessionCallback = dyn Fn(&mut SslRef, SslSession) + Send + Sync;
pub(crate) type RemoveSessionCallback = dyn Fn(&SslContextRef, &SslSessionRef) + Send + Sync;
pub(crate) type GetSessionCallback =
    dyn Fn(&mut SslRef, &[u8]) -> Result<Option<SslSession>, GetSessionPendingError> + Send + Sync;
pub(crate) type KeylogCallback = dyn Fn(&SslRef, &str) + Send + Sync;
pub(crate) type InfoCallback =
    dyn Fn(&SslRef, SslInfoCallbackMode, SslInfoCallbackValue) + Send + Sync;

pub(crate) trait CertificateCompressorAdapter: Send + Sync {
    fn compress(&self, input: &[u8], output: &mut dyn Write) -> std::io::Result<()>;
    fn decompress(&self, input: &[u8], output: &mut dyn Write) -> std::io::Result<()>;
}

struct CertificateCompressorImpl<C>(C);

impl<C: CertificateCompressor> CertificateCompressorAdapter for CertificateCompressorImpl<C> {
    fn compress(&self, input: &[u8], mut output: &mut dyn Write) -> std::io::Result<()> {
        self.0.compress(input, &mut output)
    }

    fn decompress(&self, input: &[u8], mut output: &mut dyn Write) -> std::io::Result<()> {
        self.0.decompress(input, &mut output)
    }
}

#[derive(Default)]
pub(crate) struct SslContextCallbacks {
    pub(crate) cert_verify: Option<Box<CertVerifyCallback>>,
    pub(crate) verify: Option<Box<VerifyCallback>>,
    pub(crate) custom_verify: Option<Box<CustomVerifyCallback>>,
    pub(crate) servername: Option<Box<ServernameCallback>>,
    pub(crate) ticket_key: Option<Box<TicketKeyCallback>>,
    pub(crate) alpn_select: Option<Box<AlpnSelectCallback>>,
    pub(crate) select_certificate: Option<Box<SelectCertificateCallback>>,
    pub(crate) status: Option<Box<StatusCallback>>,
    pub(crate) psk_client: Option<Box<PskClientCallback>>,
    pub(crate) psk_server: Option<Box<PskServerCallback>>,
    pub(crate) new_session: Option<Box<NewSessionCallback>>,
    pub(crate) remove_session: Option<Box<RemoveSessionCallback>>,
    pub(crate) get_session: Option<Box<GetSessionCallback>>,
    pub(crate) keylog: Option<Box<KeylogCallback>>,
    pub(crate) info: Option<Box<InfoCallback>>,
    pub(crate) private_key_method: Option<Box<dyn PrivateKeyMethod>>,
    certificate_compressors: HashMap<u16, Box<dyn CertificateCompressorAdapter>>,
}

impl SslContextCallbacks {
    pub(crate) fn insert_certificate_compressor<C: CertificateCompressor>(
        &mut self,
        compressor: C,
    ) {
        self.certificate_compressors.insert(
            C::ALGORITHM.0,
            Box::new(CertificateCompressorImpl(compressor)),
        );
    }

    fn certificate_compressor<C: CertificateCompressor>(
        &self,
    ) -> Option<&dyn CertificateCompressorAdapter> {
        self.certificate_compressors
            .get(&C::ALGORITHM.0)
            .map(Box::as_ref)
    }
}

impl fmt::Debug for SslContextCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut callbacks = f.debug_set();
        for (configured, name) in [
            (self.cert_verify.is_some(), "cert_verify"),
            (self.verify.is_some(), "verify"),
            (self.custom_verify.is_some(), "custom_verify"),
            (self.servername.is_some(), "servername"),
            (self.ticket_key.is_some(), "ticket_key"),
            (self.alpn_select.is_some(), "alpn_select"),
            (self.select_certificate.is_some(), "select_certificate"),
            (self.status.is_some(), "status"),
            (self.psk_client.is_some(), "psk_client"),
            (self.psk_server.is_some(), "psk_server"),
            (self.new_session.is_some(), "new_session"),
            (self.remove_session.is_some(), "remove_session"),
            (self.get_session.is_some(), "get_session"),
            (self.keylog.is_some(), "keylog"),
            (self.info.is_some(), "info"),
            (self.private_key_method.is_some(), "private_key_method"),
        ] {
            if configured {
                callbacks.entry(&name);
            }
        }
        for algorithm in self.certificate_compressors.keys() {
            callbacks.entry(&format_args!("certificate_compression({algorithm})"));
        }
        callbacks.finish()
    }
}

#[derive(Default)]
pub(crate) struct SslCallbacks {
    pub(crate) verify: Option<Arc<VerifyCallback>>,
    pub(crate) custom_verify: Option<Arc<CustomVerifyCallback>>,
}

pub extern "C" fn raw_verify(preverify_ok: c_int, x509_ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    ctx.with_session_callbacks(|callbacks, ctx| {
        c_int::from(callbacks
            .verify
            .as_ref()
            .expect("BUG: verify callback missing")(
            preverify_ok != 0, ctx
        ))
    })
}

pub(super) unsafe extern "C" fn raw_custom_verify(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t {
    let callback = |ssl: &mut SslRef| {
        ssl.with_session_callbacks(|callbacks, ssl| {
            callbacks
                .custom_verify
                .as_ref()
                .expect("BUG: custom verify callback missing")(ssl)
        })
    };

    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

pub(super) unsafe extern "C" fn raw_cert_verify(
    x509_ctx: *mut ffi::X509_STORE_CTX,
    _arg: *mut c_void,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let context = ctx
        .ssl()
        .expect("BUG: store context missing SSL")
        .ssl_context()
        .to_owned();
    let callback = context
        .callbacks()
        .and_then(|callbacks| callbacks.cert_verify.as_ref())
        .expect("BUG: certificate verification callback missing");

    c_int::from(callback(ctx))
}

pub(super) unsafe extern "C" fn ssl_raw_custom_verify(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
) -> ffi::ssl_verify_result_t {
    let callback = |ssl: &mut SslRef| {
        let callback = ssl
            .ownership()
            .callbacks
            .as_ref()
            .and_then(|callbacks| callbacks.custom_verify.as_ref())
            .expect("BUG: SSL custom verify callback missing")
            .clone();

        callback(ssl)
    };

    unsafe { raw_custom_verify_callback(ssl, out_alert, callback) }
}

unsafe fn raw_custom_verify_callback(
    ssl: *mut ffi::SSL,
    out_alert: *mut u8,
    callback: impl FnOnce(&mut SslRef) -> Result<(), SslVerifyError>,
) -> ffi::ssl_verify_result_t {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let out_alert = unsafe { &mut *out_alert };

    match callback(ssl) {
        Ok(()) => ffi::ssl_verify_result_t::ssl_verify_ok,
        Err(SslVerifyError::Invalid(alert)) => {
            *out_alert = alert.0 as u8;

            ffi::ssl_verify_result_t::ssl_verify_invalid
        }
        Err(SslVerifyError::Retry) => ffi::ssl_verify_result_t::ssl_verify_retry,
    }
}

pub(super) unsafe extern "C" fn raw_client_psk(
    ssl_ptr: *mut ffi::SSL,
    hint: *const c_char,
    identity: *mut c_char,
    max_identity_len: c_uint,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint {
    // SAFETY: boring provides valid inputs.

    let ssl = unsafe { SslRef::from_ptr_mut(ssl_ptr) };

    let hint = if hint.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(hint) }.to_bytes())
    };

    // Give the callback mutable slices into which it can write the identity and psk.
    let identity_sl =
        unsafe { slice::from_raw_parts_mut(identity.cast::<u8>(), max_identity_len as usize) };
    let psk_sl = unsafe { slice::from_raw_parts_mut(psk, max_psk_len as usize) };

    let result = ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .psk_client
            .as_ref()
            .expect("BUG: client PSK callback missing")(ssl, hint, identity_sl, psk_sl)
    });

    match result {
        Ok(psk_len) => psk_len as u32,
        Err(e) => {
            e.put();
            0
        }
    }
}

pub(super) unsafe extern "C" fn raw_server_psk(
    ssl: *mut ffi::SSL,
    identity: *const c_char,
    psk: *mut c_uchar,
    max_psk_len: c_uint,
) -> c_uint {
    // SAFETY: boring provides valid inputs.

    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let identity = if identity.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(identity) }.to_bytes())
    };

    // Give the callback mutable slices into which it can write the psk.
    let psk_sl = unsafe { slice::from_raw_parts_mut(psk, max_psk_len as usize) };

    let result = ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .psk_server
            .as_ref()
            .expect("BUG: server PSK callback missing")(ssl, identity, psk_sl)
    });

    match result {
        Ok(psk_len) => psk_len as u32,
        Err(e) => {
            e.put();
            0
        }
    }
}

pub(super) unsafe extern "C" fn ssl_raw_verify(
    preverify_ok: c_int,
    x509_ctx: *mut ffi::X509_STORE_CTX,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(x509_ctx) };

    let callback = ctx
        .ssl()
        .expect("BUG: store context missing ssl")
        .ownership()
        .callbacks
        .as_ref()
        .and_then(|callbacks| callbacks.verify.as_ref())
        .expect("BUG: SSL verify callback missing")
        .clone();

    c_int::from(callback(preverify_ok != 0, ctx))
}

pub(super) unsafe extern "C" fn raw_sni(
    ssl: *mut ffi::SSL,
    al: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let al = unsafe { &mut *al };

    let mut alert = SslAlert(*al);
    let r = ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .servername
            .as_ref()
            .expect("BUG: servername callback missing")(ssl, &mut alert)
    });

    *al = alert.0;

    match r {
        Ok(()) => ffi::SSL_TLSEXT_ERR_OK,
        Err(e) => e.0,
    }
}

unsafe fn to_uninit<'a, T: 'a>(ptr: *mut T) -> &'a mut MaybeUninit<T> {
    assert!(!ptr.is_null());
    unsafe { &mut *ptr.cast::<MaybeUninit<T>>() }
}

pub(super) unsafe extern "C" fn raw_ticket_key(
    ssl: *mut ffi::SSL,
    key_name: *mut u8,
    iv: *mut u8,
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    hmac_ctx: *mut ffi::HMAC_CTX,
    encrypt: c_int,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    // SAFETY: the callback guarantees that key_name is 16 bytes
    let key_name =
        unsafe { to_uninit(key_name.cast::<[u8; ffi::SSL_TICKET_KEY_NAME_LEN as usize]>()) };

    // SAFETY: the callback provides 16 bytes iv
    //
    // https://github.com/google/boringssl/blob/main/ssl/ssl_session.cc#L331
    let iv = unsafe { to_uninit(iv.cast::<[u8; ffi::EVP_MAX_IV_LENGTH as usize]>()) };

    // When encrypting a new ticket, encrypt will be one.
    let encrypt = encrypt == 1;

    // Zero-initialize the key_name and iv, since the application is expected to populate these
    // fields in the encrypt mode.
    if encrypt {
        *key_name = MaybeUninit::zeroed();
        *iv = MaybeUninit::zeroed();
    }
    let key_name = unsafe { key_name.assume_init_mut() };
    let iv = unsafe { iv.assume_init_mut() };

    // The EVP_CIPHER_CTX and HMAC_CTX are owned by boringSSL.
    let evp_ctx = unsafe { CipherCtxRef::from_ptr_mut(evp_ctx) };
    let hmac_ctx = unsafe { HmacCtxRef::from_ptr_mut(hmac_ctx) };

    ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .ticket_key
            .as_ref()
            .expect("BUG: ticket key callback missing")(
            ssl, key_name, iv, evp_ctx, hmac_ctx, encrypt,
        )
        .into()
    })
}

pub(super) unsafe extern "C" fn raw_alpn_select(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    inbuf: *const c_uchar,
    inlen: c_uint,
    _arg: *mut c_void,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let protos = unsafe { slice::from_raw_parts(inbuf, inlen as usize) };
    let out = unsafe { &mut *out };
    let outlen = unsafe { &mut *outlen };

    let context = ssl.ssl_context().to_owned();
    let result = context
        .callbacks()
        .and_then(|callbacks| callbacks.alpn_select.as_ref())
        .expect("BUG: ALPN callback missing")(ssl, protos);

    match result {
        Ok(proto) => {
            *out = proto.as_ptr();
            *outlen = proto.len() as c_uchar;

            ffi::SSL_TLSEXT_ERR_OK
        }
        Err(e) => e.0,
    }
}

pub(super) unsafe extern "C" fn raw_select_cert(
    client_hello: *const ffi::SSL_CLIENT_HELLO,
) -> ffi::ssl_select_cert_result_t {
    // SAFETY: boring provides valid inputs.
    let client_hello = ClientHello(unsafe { &*client_hello });
    let ech_accepted = client_hello.ssl().ech_accepted();

    let ssl_context = client_hello.ssl().ssl_context().to_owned();
    let callback = ssl_context
        .callbacks()
        .and_then(|callbacks| callbacks.select_certificate.as_ref())
        .expect("BUG: select certificate callback missing");

    match callback(client_hello) {
        Ok(SelectCertAction::Success) => ffi::ssl_select_cert_result_t::ssl_select_cert_success,
        Ok(SelectCertAction::DisableEch) if ech_accepted => {
            ffi::ssl_select_cert_result_t::ssl_select_cert_disable_ech
        }
        Ok(SelectCertAction::DisableEch) => ffi::ssl_select_cert_result_t::ssl_select_cert_error,
        Err(e) => e.0,
    }
}

pub(super) unsafe extern "C" fn raw_tlsext_status(ssl: *mut ffi::SSL, _: *mut c_void) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let ssl_context = ssl.ssl_context().to_owned();
    let callback = ssl_context
        .callbacks()
        .and_then(|callbacks| callbacks.status.as_ref())
        .expect("BUG: status callback missing");

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

pub(super) unsafe extern "C" fn raw_new_session(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let session = unsafe { SslSession::from_ptr(session) };

    ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .new_session
            .as_ref()
            .expect("BUG: new session callback missing")(ssl, session);
    });

    // the return code doesn't indicate error vs success, but whether or not we consumed the session
    1
}

pub(super) unsafe extern "C" fn raw_remove_session(
    ctx: *mut ffi::SSL_CTX,
    session: *mut ffi::SSL_SESSION,
) {
    // SAFETY: boring provides valid inputs.
    let ctx = unsafe { SslContextRef::from_ptr(ctx) };
    let session = unsafe { SslSessionRef::from_ptr(session) };

    let callback = ctx
        .callbacks()
        .and_then(|callbacks| callbacks.remove_session.as_ref())
        .expect("BUG: remove session callback missing");

    callback(ctx, session);
}

type DataPtr = *const c_uchar;

pub(super) unsafe extern "C" fn raw_get_session(
    ssl: *mut ffi::SSL,
    data: DataPtr,
    len: c_int,
    copy: *mut c_int,
) -> *mut ffi::SSL_SESSION {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let data = unsafe { slice::from_raw_parts(data, len as usize) };
    let copy = unsafe { &mut *copy };

    let result = ssl.with_session_callbacks(|callbacks, ssl| {
        callbacks
            .get_session
            .as_ref()
            .expect("BUG: get session callback missing")(ssl, data)
    });

    match result {
        Ok(Some(session)) => {
            let p = session.into_ptr();

            *copy = 0;

            p
        }
        Ok(None) => ptr::null_mut(),
        Err(GetSessionPendingError) => unsafe { ffi::SSL_magic_pending_session_ptr() },
    }
}

pub(super) unsafe extern "C" fn raw_keylog(ssl: *const ffi::SSL, line: *const c_char) {
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
    let line = unsafe { CStr::from_ptr(line).to_string_lossy() };

    let callback = ssl
        .ssl_context()
        .callbacks()
        .and_then(|callbacks| callbacks.keylog.as_ref())
        .expect("BUG: keylog callback missing");

    callback(ssl, &line);
}

pub(super) unsafe extern "C" fn raw_sign<S>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    signature_algorithm: u16,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    S: PrivateKeyMethodSource,
{
    // SAFETY: boring provides valid inputs.
    let input = unsafe { slice::from_raw_parts(in_, in_len) };

    let signature_algorithm = SslSignatureAlgorithm(signature_algorithm);

    let callback = |method: &dyn PrivateKeyMethod, ssl: &mut _, output: &mut _| {
        method.sign(ssl, input, signature_algorithm, output)
    };

    // SAFETY: boring provides valid inputs.
    unsafe { raw_private_key_callback::<S>(ssl, out, out_len, max_out, callback) }
}

pub(super) unsafe extern "C" fn raw_decrypt<S>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    in_: *const u8,
    in_len: usize,
) -> ffi::ssl_private_key_result_t
where
    S: PrivateKeyMethodSource,
{
    // SAFETY: boring provides valid inputs.
    let input = unsafe { slice::from_raw_parts(in_, in_len) };

    let callback = |method: &dyn PrivateKeyMethod, ssl: &mut _, output: &mut _| {
        method.decrypt(ssl, input, output)
    };

    // SAFETY: boring provides valid inputs.
    unsafe { raw_private_key_callback::<S>(ssl, out, out_len, max_out, callback) }
}

pub(super) unsafe extern "C" fn raw_complete<S>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
) -> ffi::ssl_private_key_result_t
where
    S: PrivateKeyMethodSource,
{
    // SAFETY: boring provides valid inputs.
    unsafe {
        raw_private_key_callback::<S>(ssl, out, out_len, max_out, |method, ssl, output| {
            method.complete(ssl, output)
        })
    }
}

unsafe fn raw_private_key_callback<S>(
    ssl: *mut ffi::SSL,
    out: *mut u8,
    out_len: *mut usize,
    max_out: usize,
    callback: impl FnOnce(
        &dyn PrivateKeyMethod,
        &mut SslRef,
        &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError>,
) -> ffi::ssl_private_key_result_t
where
    S: PrivateKeyMethodSource,
{
    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let output = unsafe { slice::from_raw_parts_mut(out, max_out) };
    let out_len = unsafe { &mut *out_len };

    let owner = S::get_owner(ssl).expect("BUG: private key method owner missing");
    let method = S::get_callback(&owner).expect("BUG: private key method missing");

    match callback(method, ssl, output) {
        Ok(written) => {
            assert!(written <= max_out);

            *out_len = written;

            ffi::ssl_private_key_result_t::ssl_private_key_success
        }
        Err(err) => err.0,
    }
}

pub(super) trait PrivateKeyMethodSource {
    type Owner;

    fn get_owner(ssl: &SslRef) -> Option<Self::Owner>;

    fn get_callback(owner: &Self::Owner) -> Option<&dyn PrivateKeyMethod>;
}

pub(super) unsafe extern "C" fn raw_info_callback(ssl: *const ffi::SSL, mode: c_int, value: c_int) {
    // Due to FFI signature requirements we have to pass a *const SSL into this function, but
    // foreign-types requires a *mut SSL to get the Rust SslRef
    let mut_ref = ssl.cast_mut();

    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr(mut_ref) };
    let ssl_context = ssl.ssl_context();

    let callback = ssl_context
        .callbacks()
        .and_then(|callbacks| callbacks.info.as_ref())
        .expect("BUG: info callback missing");

    let value = match mode {
        ffi::SSL_CB_READ_ALERT | ffi::SSL_CB_WRITE_ALERT => {
            SslInfoCallbackValue::Alert(SslInfoCallbackAlert(value))
        }
        _ => SslInfoCallbackValue::Unit,
    };

    callback(ssl, SslInfoCallbackMode(mode), value);
}

pub(super) unsafe extern "C" fn raw_ssl_cert_compress<C>(
    ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    const {
        assert!(C::CAN_COMPRESS);
    }

    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let ssl_context = ssl.ssl_context();
    let compressor = ssl_context
        .callbacks()
        .and_then(SslContextCallbacks::certificate_compressor::<C>)
        .expect("BUG: certificate compression missed");

    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let mut writer = CryptoByteBuilder::from_ptr(out);
    if compressor.compress(input_slice, &mut writer).is_err() {
        return 0;
    }

    1
}

pub(super) unsafe extern "C" fn raw_ssl_cert_decompress<C>(
    ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int
where
    C: CertificateCompressor,
{
    const {
        assert!(C::CAN_DECOMPRESS);
    }

    // SAFETY: boring provides valid inputs.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };

    let ssl_context = ssl.ssl_context();
    let compressor = ssl_context
        .callbacks()
        .and_then(SslContextCallbacks::certificate_compressor::<C>)
        .expect("BUG: certificate compression missed");

    let Ok(mut decompression_buffer) = CryptoBufferBuilder::with_capacity(uncompressed_len) else {
        return 0;
    };

    let input_slice = unsafe { slice::from_raw_parts(input, input_len) };

    if compressor
        .decompress(input_slice, decompression_buffer.as_writer())
        .is_err()
    {
        return 0;
    }

    let Ok(crypto_buffer) = decompression_buffer.build() else {
        return 0;
    };

    unsafe { *out = crypto_buffer };
    1
}

struct CryptoByteBuilder<'a>(*mut ffi::CBB, std::marker::PhantomData<&'a [u8]>);

impl CryptoByteBuilder<'_> {
    fn from_ptr(ptr: *mut ffi::CBB) -> Self {
        Self(ptr, Default::default())
    }
}

impl std::io::Write for CryptoByteBuilder<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let success = unsafe { ffi::CBB_add_bytes(self.0, buf.as_ptr(), buf.len()) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_add_bytes failed"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let success = unsafe { ffi::CBB_flush(self.0) == 1 };
        if !success {
            return Err(std::io::Error::other("CBB_flush failed"));
        }
        Ok(())
    }
}

struct CryptoBufferBuilder<'a> {
    buffer: *mut ffi::CRYPTO_BUFFER,
    cursor: std::io::Cursor<&'a mut [u8]>,
}

impl<'a> CryptoBufferBuilder<'a> {
    fn with_capacity(capacity: usize) -> Result<CryptoBufferBuilder<'a>, ErrorStack> {
        let mut data: *mut u8 = ptr::null_mut();
        let buffer = unsafe { crate::cvt_p(ffi::CRYPTO_BUFFER_alloc(&mut data, capacity))? };
        Ok(CryptoBufferBuilder {
            buffer,
            cursor: std::io::Cursor::new(unsafe { slice::from_raw_parts_mut(data, capacity) }),
        })
    }

    fn as_writer(&mut self) -> &mut (impl std::io::Write + 'a) {
        &mut self.cursor
    }

    fn build(mut self) -> Result<*mut ffi::CRYPTO_BUFFER, ErrorStack> {
        let buffer_capacity = unsafe { ffi::CRYPTO_BUFFER_len(self.buffer) };
        if self.cursor.position() != buffer_capacity as u64 {
            // Make sure all bytes in buffer initialized as required by Boring SSL.
            return Err(ErrorStack::internal_error_str("invalid len"));
        }
        // Drop is no-op if the buffer is null
        Ok(mem::replace(&mut self.buffer, ptr::null_mut()))
    }
}

impl Drop for CryptoBufferBuilder<'_> {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            unsafe {
                boring_sys::CRYPTO_BUFFER_free(self.buffer);
            }
        }
    }
}
