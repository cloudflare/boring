//! SSL/TLS support.
//!
//! `SslConnector` and `SslAcceptor` should be used in most cases - they handle
//! configuration of the OpenSSL primitives for you.
//!
//! # Examples
//!
//! To connect as a client to a remote server:
//!
//! ```no_run
//! use boring::ssl::{SslMethod, SslConnector};
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = connector.connect("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```
//!
//! To accept connections as a server from remote clients:
//!
//! ```no_run
//! use boring::ssl::{SslMethod, SslAcceptor, SslStream, SslFiletype};
//! use std::net::{TcpListener, TcpStream};
//! use std::sync::Arc;
//! use std::thread;
//!
//!
//! let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
//! acceptor.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
//! acceptor.set_certificate_chain_file("certs.pem").unwrap();
//! acceptor.check_private_key().unwrap();
//! let acceptor = Arc::new(acceptor.build());
//!
//! let listener = TcpListener::bind("0.0.0.0:8443").unwrap();
//!
//! fn handle_client(stream: SslStream<TcpStream>) {
//!     // ...
//! }
//!
//! for stream in listener.incoming() {
//!     match stream {
//!         Ok(stream) => {
//!             let acceptor = acceptor.clone();
//!             thread::spawn(move || {
//!                 let stream = acceptor.accept(stream).unwrap();
//!                 handle_client(stream);
//!             });
//!         }
//!         Err(e) => { /* connection failed */ }
//!     }
//! }
//! ```
use ffi;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};
use libc::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use std::any::TypeId;
use std::cmp;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop};
use std::ops::{Deref, DerefMut};
use std::panic::resume_unwind;
use std::path::Path;
use std::ptr;
use std::slice;
use std::str;
use std::sync::{Arc, Mutex};

use dh::DhRef;
use ec::EcKeyRef;
use error::ErrorStack;
use ex_data::Index;
use nid::Nid;
use pkey::{HasPrivate, PKeyRef, Params, Private};
use srtp::{SrtpProtectionProfile, SrtpProtectionProfileRef};
use ssl::bio::BioMethod;
use ssl::callbacks::*;
use ssl::error::InnerError;
use stack::{Stack, StackRef};
use x509::store::{X509Store, X509StoreBuilderRef, X509StoreRef};
use x509::verify::X509VerifyParamRef;
use x509::{X509Name, X509Ref, X509StoreContextRef, X509VerifyResult, X509};
use {cvt, cvt_0i, cvt_n, cvt_p, init};

pub use ssl::connector::{
    ConnectConfiguration, SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder,
};
pub use ssl::error::{Error, ErrorCode, HandshakeError};

mod bio;
mod callbacks;
mod connector;
mod error;
#[cfg(test)]
mod test;

bitflags! {
    /// Options controlling the behavior of an `SslContext`.
    pub struct SslOptions: c_uint {
        /// Disables a countermeasure against an SSLv3/TLSv1.0 vulnerability affecting CBC ciphers.
        const DONT_INSERT_EMPTY_FRAGMENTS = ffi::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS as _;

        /// A "reasonable default" set of options which enables compatibility flags.
        const ALL = ffi::SSL_OP_ALL as _;

        /// Do not query the MTU.
        ///
        /// Only affects DTLS connections.
        const NO_QUERY_MTU = ffi::SSL_OP_NO_QUERY_MTU as _;

        /// Disables the use of session tickets for session resumption.
        const NO_TICKET = ffi::SSL_OP_NO_TICKET as _;

        /// Always start a new session when performing a renegotiation on the server side.
        const NO_SESSION_RESUMPTION_ON_RENEGOTIATION =
            ffi::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION as _;

        /// Disables the use of TLS compression.
        const NO_COMPRESSION = ffi::SSL_OP_NO_COMPRESSION as _;

        /// Allow legacy insecure renegotiation with servers or clients that do not support secure
        /// renegotiation.
        const ALLOW_UNSAFE_LEGACY_RENEGOTIATION =
            ffi::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION as _;

        /// Creates a new key for each session when using ECDHE.
        const SINGLE_ECDH_USE = ffi::SSL_OP_SINGLE_ECDH_USE as _;

        /// Creates a new key for each session when using DHE.
        const SINGLE_DH_USE = ffi::SSL_OP_SINGLE_DH_USE as _;

        /// Use the server's preferences rather than the client's when selecting a cipher.
        ///
        /// This has no effect on the client side.
        const CIPHER_SERVER_PREFERENCE = ffi::SSL_OP_CIPHER_SERVER_PREFERENCE as _;

        /// Disables version rollback attach detection.
        const TLS_ROLLBACK_BUG = ffi::SSL_OP_TLS_ROLLBACK_BUG as _;

        /// Disables the use of SSLv2.
        const NO_SSLV2 = ffi::SSL_OP_NO_SSLv2 as _;

        /// Disables the use of SSLv3.
        const NO_SSLV3 = ffi::SSL_OP_NO_SSLv3 as _;

        /// Disables the use of TLSv1.0.
        const NO_TLSV1 = ffi::SSL_OP_NO_TLSv1 as _;

        /// Disables the use of TLSv1.1.
        const NO_TLSV1_1 = ffi::SSL_OP_NO_TLSv1_1 as _;

        /// Disables the use of TLSv1.2.
        const NO_TLSV1_2 = ffi::SSL_OP_NO_TLSv1_2 as _;

        /// Disables the use of TLSv1.3.
        const NO_TLSV1_3 = ffi::SSL_OP_NO_TLSv1_3 as _;

        /// Disables the use of DTLSv1.0
        const NO_DTLSV1 = ffi::SSL_OP_NO_DTLSv1 as _;

        /// Disables the use of DTLSv1.2.
        const NO_DTLSV1_2 = ffi::SSL_OP_NO_DTLSv1_2 as _;

        /// Disallow all renegotiation in TLSv1.2 and earlier.
        const NO_RENEGOTIATION = ffi::SSL_OP_NO_RENEGOTIATION as _;
    }
}

bitflags! {
    /// Options controlling the behavior of an `SslContext`.
    pub struct SslMode: c_uint {
        /// Enables "short writes".
        ///
        /// Normally, a write in OpenSSL will always write out all of the requested data, even if it
        /// requires more than one TLS record or write to the underlying stream. This option will
        /// cause a write to return after writing a single TLS record instead.
        const ENABLE_PARTIAL_WRITE = ffi::SSL_MODE_ENABLE_PARTIAL_WRITE as _;

        /// Disables a check that the data buffer has not moved between calls when operating in a
        /// nonblocking context.
        const ACCEPT_MOVING_WRITE_BUFFER = ffi::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER as _;

        /// Enables automatic retries after TLS session events such as renegotiations or heartbeats.
        ///
        /// By default, OpenSSL will return a `WantRead` error after a renegotiation or heartbeat.
        /// This option will cause OpenSSL to automatically continue processing the requested
        /// operation instead.
        ///
        /// Note that `SslStream::read` and `SslStream::write` will automatically retry regardless
        /// of the state of this option. It only affects `SslStream::ssl_read` and
        /// `SslStream::ssl_write`.
        const AUTO_RETRY = ffi::SSL_MODE_AUTO_RETRY as _;

        /// Disables automatic chain building when verifying a peer's certificate.
        ///
        /// TLS peers are responsible for sending the entire certificate chain from the leaf to a
        /// trusted root, but some will incorrectly not do so. OpenSSL will try to build the chain
        /// out of certificates it knows of, and this option will disable that behavior.
        const NO_AUTO_CHAIN = ffi::SSL_MODE_NO_AUTO_CHAIN as _;

        /// Release memory buffers when the session does not need them.
        ///
        /// This saves ~34 KiB of memory for idle streams.
        const RELEASE_BUFFERS = ffi::SSL_MODE_RELEASE_BUFFERS as _;

        /// Sends the fake `TLS_FALLBACK_SCSV` cipher suite in the ClientHello message of a
        /// handshake.
        ///
        /// This should only be enabled if a client has failed to connect to a server which
        /// attempted to downgrade the protocol version of the session.
        ///
        /// Do not use this unless you know what you're doing!
        const SEND_FALLBACK_SCSV = ffi::SSL_MODE_SEND_FALLBACK_SCSV as _;
    }
}

/// A type specifying the kind of protocol an `SslContext` will speak.
#[derive(Copy, Clone)]
pub struct SslMethod(*const ffi::SSL_METHOD);

impl SslMethod {
    /// Support all versions of the TLS protocol.
    ///
    /// This corresponds to `TLS_method` on OpenSSL 1.1.0 and `SSLv23_method`
    /// on OpenSSL 1.0.x.
    pub fn tls() -> SslMethod {
        unsafe { SslMethod(TLS_method()) }
    }

    /// Support all versions of the DTLS protocol.
    ///
    /// This corresponds to `DTLS_method` on OpenSSL 1.1.0 and `DTLSv1_method`
    /// on OpenSSL 1.0.x.
    pub fn dtls() -> SslMethod {
        unsafe { SslMethod(DTLS_method()) }
    }

    /// Support all versions of the TLS protocol, explicitly as a client.
    ///
    /// This corresponds to `TLS_client_method` on OpenSSL 1.1.0 and
    /// `SSLv23_client_method` on OpenSSL 1.0.x.
    pub fn tls_client() -> SslMethod {
        unsafe { SslMethod(TLS_client_method()) }
    }

    /// Support all versions of the TLS protocol, explicitly as a server.
    ///
    /// This corresponds to `TLS_server_method` on OpenSSL 1.1.0 and
    /// `SSLv23_server_method` on OpenSSL 1.0.x.
    pub fn tls_server() -> SslMethod {
        unsafe { SslMethod(TLS_server_method()) }
    }

    /// Constructs an `SslMethod` from a pointer to the underlying OpenSSL value.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is valid.
    pub unsafe fn from_ptr(ptr: *const ffi::SSL_METHOD) -> SslMethod {
        SslMethod(ptr)
    }

    /// Returns a pointer to the underlying OpenSSL value.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_ptr(&self) -> *const ffi::SSL_METHOD {
        self.0
    }
}

unsafe impl Sync for SslMethod {}
unsafe impl Send for SslMethod {}

bitflags! {
    /// Options controling the behavior of certificate verification.
    pub struct SslVerifyMode: i32 {
        /// Verifies that the peer's certificate is trusted.
        ///
        /// On the server side, this will cause OpenSSL to request a certificate from the client.
        const PEER = ffi::SSL_VERIFY_PEER;

        /// Disables verification of the peer's certificate.
        ///
        /// On the server side, this will cause OpenSSL to not request a certificate from the
        /// client. On the client side, the certificate will be checked for validity, but the
        /// negotiation will continue regardless of the result of that check.
        const NONE = ffi::SSL_VERIFY_NONE;

        /// On the server side, abort the handshake if the client did not send a certificate.
        ///
        /// This should be paired with `SSL_VERIFY_PEER`. It has no effect on the client side.
        const FAIL_IF_NO_PEER_CERT = ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
}

bitflags! {
    /// Options controlling the behavior of session caching.
    pub struct SslSessionCacheMode: c_int {
        /// No session caching for the client or server takes place.
        const OFF = ffi::SSL_SESS_CACHE_OFF;

        /// Enable session caching on the client side.
        ///
        /// OpenSSL has no way of identifying the proper session to reuse automatically, so the
        /// application is responsible for setting it explicitly via [`SslRef::set_session`].
        ///
        /// [`SslRef::set_session`]: struct.SslRef.html#method.set_session
        const CLIENT = ffi::SSL_SESS_CACHE_CLIENT;

        /// Enable session caching on the server side.
        ///
        /// This is the default mode.
        const SERVER = ffi::SSL_SESS_CACHE_SERVER;

        /// Enable session caching on both the client and server side.
        const BOTH = ffi::SSL_SESS_CACHE_BOTH;

        /// Disable automatic removal of expired sessions from the session cache.
        const NO_AUTO_CLEAR = ffi::SSL_SESS_CACHE_NO_AUTO_CLEAR;

        /// Disable use of the internal session cache for session lookups.
        const NO_INTERNAL_LOOKUP = ffi::SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;

        /// Disable use of the internal session cache for session storage.
        const NO_INTERNAL_STORE = ffi::SSL_SESS_CACHE_NO_INTERNAL_STORE;

        /// Disable use of the internal session cache for storage and lookup.
        const NO_INTERNAL = ffi::SSL_SESS_CACHE_NO_INTERNAL;
    }
}

/// An identifier of the format of a certificate or key file.
#[derive(Copy, Clone)]
pub struct SslFiletype(c_int);

impl SslFiletype {
    /// The PEM format.
    ///
    /// This corresponds to `SSL_FILETYPE_PEM`.
    pub const PEM: SslFiletype = SslFiletype(ffi::SSL_FILETYPE_PEM);

    /// The ASN1 format.
    ///
    /// This corresponds to `SSL_FILETYPE_ASN1`.
    pub const ASN1: SslFiletype = SslFiletype(ffi::SSL_FILETYPE_ASN1);

    /// Constructs an `SslFiletype` from a raw OpenSSL value.
    pub fn from_raw(raw: c_int) -> SslFiletype {
        SslFiletype(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

/// An identifier of a certificate status type.
#[derive(Copy, Clone)]
pub struct StatusType(c_int);

impl StatusType {
    /// An OSCP status.
    pub const OCSP: StatusType = StatusType(ffi::TLSEXT_STATUSTYPE_ocsp);

    /// Constructs a `StatusType` from a raw OpenSSL value.
    pub fn from_raw(raw: c_int) -> StatusType {
        StatusType(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

/// An identifier of a session name type.
#[derive(Copy, Clone)]
pub struct NameType(c_int);

impl NameType {
    /// A host name.
    pub const HOST_NAME: NameType = NameType(ffi::TLSEXT_NAMETYPE_host_name);

    /// Constructs a `StatusType` from a raw OpenSSL value.
    pub fn from_raw(raw: c_int) -> StatusType {
        StatusType(raw)
    }

    /// Returns the raw OpenSSL value represented by this type.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

lazy_static! {
    static ref INDEXES: Mutex<HashMap<TypeId, c_int>> = Mutex::new(HashMap::new());
    static ref SSL_INDEXES: Mutex<HashMap<TypeId, c_int>> = Mutex::new(HashMap::new());
    static ref SESSION_CTX_INDEX: Index<Ssl, SslContext> = Ssl::new_ex_index().unwrap();
}

unsafe extern "C" fn free_data_box<T>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        Box::<T>::from_raw(ptr as *mut T);
    }
}

/// An error returned from the SNI callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SniError(c_int);

impl SniError {
    /// Abort the handshake with a fatal alert.
    pub const ALERT_FATAL: SniError = SniError(ffi::SSL_TLSEXT_ERR_ALERT_FATAL);

    /// Send a warning alert to the client and continue the handshake.
    pub const ALERT_WARNING: SniError = SniError(ffi::SSL_TLSEXT_ERR_ALERT_WARNING);

    pub const NOACK: SniError = SniError(ffi::SSL_TLSEXT_ERR_NOACK);
}

/// An SSL/TLS alert.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslAlert(c_int);

impl SslAlert {
    /// Alert 112 - `unrecognized_name`.
    pub const UNRECOGNIZED_NAME: SslAlert = SslAlert(ffi::SSL_AD_UNRECOGNIZED_NAME);
    pub const ILLEGAL_PARAMETER: SslAlert = SslAlert(ffi::SSL_AD_ILLEGAL_PARAMETER);
    pub const DECODE_ERROR: SslAlert = SslAlert(ffi::SSL_AD_DECODE_ERROR);
}

/// An error returned from an ALPN selection callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AlpnError(c_int);

impl AlpnError {
    /// Terminate the handshake with a fatal alert.
    pub const ALERT_FATAL: AlpnError = AlpnError(ffi::SSL_TLSEXT_ERR_ALERT_FATAL);

    /// Do not select a protocol, but continue the handshake.
    pub const NOACK: AlpnError = AlpnError(ffi::SSL_TLSEXT_ERR_NOACK);
}

/// An error returned from a certificate selection callback.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SelectCertError(ffi::ssl_select_cert_result_t);

impl SelectCertError {
    /// A fatal error occured and the handshake should be terminated.
    pub const ERROR: Self = Self(ffi::ssl_select_cert_result_t::ssl_select_cert_error);
}

/// Extension types, to be used with `ClientHello::get_extension`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExtensionType(u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(ffi::TLSEXT_TYPE_server_name as u16);
    pub const STATUS_REQUEST: Self = Self(ffi::TLSEXT_TYPE_status_request as u16);
    pub const EC_POINT_FORMATS: Self = Self(ffi::TLSEXT_TYPE_ec_point_formats as u16);
    pub const SIGNATURE_ALGORITHMS: Self = Self(ffi::TLSEXT_TYPE_signature_algorithms as u16);
    pub const SRTP: Self = Self(ffi::TLSEXT_TYPE_srtp as u16);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self =
        Self(ffi::TLSEXT_TYPE_application_layer_protocol_negotiation as u16);
    pub const PADDING: Self = Self(ffi::TLSEXT_TYPE_padding as u16);
    pub const EXTENDED_MASTER_SECRET: Self = Self(ffi::TLSEXT_TYPE_extended_master_secret as u16);
    pub const TOKEN_BINDING: Self = Self(ffi::TLSEXT_TYPE_token_binding as u16);
    pub const QUIC_TRANSPORT_PARAMETERS_LEGACY: Self =
        Self(ffi::TLSEXT_TYPE_quic_transport_parameters_legacy as u16);
    pub const QUIC_TRANSPORT_PARAMETERS_STANDARD: Self =
        Self(ffi::TLSEXT_TYPE_quic_transport_parameters_standard as u16);
    pub const CERT_COMPRESSION: Self = Self(ffi::TLSEXT_TYPE_cert_compression as u16);
    pub const SESSION_TICKET: Self = Self(ffi::TLSEXT_TYPE_session_ticket as u16);
    pub const SUPPORTED_GROUPS: Self = Self(ffi::TLSEXT_TYPE_supported_groups as u16);
    pub const PRE_SHARED_KEY: Self = Self(ffi::TLSEXT_TYPE_pre_shared_key as u16);
    pub const EARLY_DATA: Self = Self(ffi::TLSEXT_TYPE_early_data as u16);
    pub const SUPPORTED_VERSIONS: Self = Self(ffi::TLSEXT_TYPE_supported_versions as u16);
    pub const COOKIE: Self = Self(ffi::TLSEXT_TYPE_cookie as u16);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(ffi::TLSEXT_TYPE_psk_key_exchange_modes as u16);
    pub const CERTIFICATE_AUTHORITIES: Self = Self(ffi::TLSEXT_TYPE_certificate_authorities as u16);
    pub const SIGNATURE_ALGORITHMS_CERT: Self =
        Self(ffi::TLSEXT_TYPE_signature_algorithms_cert as u16);
    pub const KEY_SHARE: Self = Self(ffi::TLSEXT_TYPE_key_share as u16);
    pub const RENEGOTIATE: Self = Self(ffi::TLSEXT_TYPE_renegotiate as u16);
    pub const DELEGATED_CREDENTIAL: Self = Self(ffi::TLSEXT_TYPE_delegated_credential as u16);
    pub const APPLICATION_SETTINGS: Self = Self(ffi::TLSEXT_TYPE_application_settings as u16);
    pub const ENCRYPTED_CLIENT_HELLO: Self = Self(ffi::TLSEXT_TYPE_encrypted_client_hello as u16);
    pub const ECH_IS_INNER: Self = Self(ffi::TLSEXT_TYPE_ech_is_inner as u16);
    pub const CERTIFICATE_TIMESTAMP: Self = Self(ffi::TLSEXT_TYPE_certificate_timestamp as u16);
    pub const NEXT_PROTO_NEG: Self = Self(ffi::TLSEXT_TYPE_next_proto_neg as u16);
    pub const CHANNEL_ID: Self = Self(ffi::TLSEXT_TYPE_channel_id as u16);
}

impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// An SSL/TLS protocol version.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslVersion(u16);

impl SslVersion {
    /// SSLv3
    pub const SSL3: SslVersion = SslVersion(ffi::SSL3_VERSION as _);

    /// TLSv1.0
    pub const TLS1: SslVersion = SslVersion(ffi::TLS1_VERSION as _);

    /// TLSv1.1
    pub const TLS1_1: SslVersion = SslVersion(ffi::TLS1_1_VERSION as _);

    /// TLSv1.2
    pub const TLS1_2: SslVersion = SslVersion(ffi::TLS1_2_VERSION as _);

    /// TLSv1.3
    pub const TLS1_3: SslVersion = SslVersion(ffi::TLS1_3_VERSION as _);
}

/// A signature verification algorithm.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslSignatureAlgorithm(u16);

impl SslSignatureAlgorithm {
    pub const RSA_PKCS1_SHA1: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PKCS1_SHA1 as _);

    pub const RSA_PKCS1_SHA256: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PKCS1_SHA256 as _);

    pub const RSA_PKCS1_SHA384: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PKCS1_SHA384 as _);

    pub const RSA_PKCS1_SHA512: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PKCS1_SHA512 as _);

    pub const ECDSA_SHA1: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_ECDSA_SHA1 as _);

    pub const ECDSA_SECP256R1_SHA256: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_ECDSA_SECP256R1_SHA256 as _);

    pub const ECDSA_SECP384R1_SHA384: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_ECDSA_SECP384R1_SHA384 as _);

    pub const ECDSA_SECP521R1_SHA512: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_ECDSA_SECP521R1_SHA512 as _);

    pub const RSA_PSS_RSAE_SHA256: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA256 as _);

    pub const RSA_PSS_RSAE_SHA384: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA384 as _);

    pub const RSA_PSS_RSAE_SHA512: SslSignatureAlgorithm =
        SslSignatureAlgorithm(ffi::SSL_SIGN_RSA_PSS_RSAE_SHA512 as _);

    pub const ED25519: SslSignatureAlgorithm = SslSignatureAlgorithm(ffi::SSL_SIGN_ED25519 as _);
}

/// A TLS Curve.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SslCurve(c_int);

impl SslCurve {
    pub const SECP224R1: SslCurve = SslCurve(ffi::NID_secp224r1);

    pub const SECP256R1: SslCurve = SslCurve(ffi::NID_X9_62_prime256v1);

    pub const SECP384R1: SslCurve = SslCurve(ffi::NID_secp384r1);

    pub const SECP521R1: SslCurve = SslCurve(ffi::NID_secp521r1);

    pub const X25519: SslCurve = SslCurve(ffi::NID_X25519);

    pub const CECPQ2: SslCurve = SslCurve(ffi::NID_CECPQ2);
}

/// A standard implementation of protocol selection for Application Layer Protocol Negotiation
/// (ALPN).
///
/// `server` should contain the server's list of supported protocols and `client` the client's. They
/// must both be in the ALPN wire format. See the documentation for
/// [`SslContextBuilder::set_alpn_protos`] for details.
///
/// It will select the first protocol supported by the server which is also supported by the client.
///
/// This corresponds to [`SSL_select_next_proto`].
///
/// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
/// [`SSL_select_next_proto`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_alpn_protos.html
pub fn select_next_proto<'a>(server: &[u8], client: &'a [u8]) -> Option<&'a [u8]> {
    unsafe {
        let mut out = ptr::null_mut();
        let mut outlen = 0;
        let r = ffi::SSL_select_next_proto(
            &mut out,
            &mut outlen,
            server.as_ptr(),
            server.len() as c_uint,
            client.as_ptr(),
            client.len() as c_uint,
        );
        if r == ffi::OPENSSL_NPN_NEGOTIATED {
            Some(slice::from_raw_parts(out as *const u8, outlen as usize))
        } else {
            None
        }
    }
}

/// A builder for `SslContext`s.
pub struct SslContextBuilder(SslContext);

impl SslContextBuilder {
    /// Creates a new `SslContextBuilder`.
    ///
    /// This corresponds to [`SSL_CTX_new`].
    ///
    /// [`SSL_CTX_new`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_new.html
    pub fn new(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        unsafe {
            init();
            let ctx = cvt_p(ffi::SSL_CTX_new(method.as_ptr()))?;

            Ok(SslContextBuilder::from_ptr(ctx))
        }
    }

    /// Creates an `SslContextBuilder` from a pointer to a raw OpenSSL value.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the pointer is valid and uniquely owned by the builder.
    pub unsafe fn from_ptr(ctx: *mut ffi::SSL_CTX) -> SslContextBuilder {
        SslContextBuilder(SslContext::from_ptr(ctx))
    }

    /// Returns a pointer to the raw OpenSSL value.
    pub fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.0.as_ptr()
    }

    /// Configures the certificate verification method for new connections.
    ///
    /// This corresponds to [`SSL_CTX_set_verify`].
    ///
    /// [`SSL_CTX_set_verify`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_verify.html
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe {
            ffi::SSL_CTX_set_verify(self.as_ptr(), mode.bits as c_int, None);
        }
    }

    /// Configures the certificate verification method for new connections and
    /// registers a verification callback.
    ///
    /// The callback is passed a boolean indicating if OpenSSL's internal verification succeeded as
    /// well as a reference to the `X509StoreContext` which can be used to examine the certificate
    /// chain. It should return a boolean indicating if verification succeeded.
    ///
    /// This corresponds to [`SSL_CTX_set_verify`].
    ///
    /// [`SSL_CTX_set_verify`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_verify.html
    pub fn set_verify_callback<F>(&mut self, mode: SslVerifyMode, verify: F)
    where
        F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), verify);
            ffi::SSL_CTX_set_verify(self.as_ptr(), mode.bits as c_int, Some(raw_verify::<F>));
        }
    }

    /// Configures the server name indication (SNI) callback for new connections.
    ///
    /// SNI is used to allow a single server to handle requests for multiple domains, each of which
    /// has its own certificate chain and configuration.
    ///
    /// Obtain the server name with the `servername` method and then set the corresponding context
    /// with `set_ssl_context`
    ///
    /// This corresponds to [`SSL_CTX_set_tlsext_servername_callback`].
    ///
    /// [`SSL_CTX_set_tlsext_servername_callback`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_tlsext_servername_callback.html
    // FIXME tlsext prefix?
    pub fn set_servername_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &mut SslAlert) -> Result<(), SniError> + 'static + Sync + Send,
    {
        unsafe {
            // The SNI callback is somewhat unique in that the callback associated with the original
            // context associated with an SSL can be used even if the SSL's context has been swapped
            // out. When that happens, we wouldn't be able to look up the callback's state in the
            // context's ex data. Instead, pass the pointer directly as the servername arg. It's
            // still stored in ex data to manage the lifetime.
            let arg = self.set_ex_data_inner(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_tlsext_servername_arg(self.as_ptr(), arg);

            let f: extern "C" fn(_, _, _) -> _ = raw_sni::<F>;
            ffi::SSL_CTX_set_tlsext_servername_callback(self.as_ptr(), Some(f));
        }
    }

    /// Sets the certificate verification depth.
    ///
    /// If the peer's certificate chain is longer than this value, verification will fail.
    ///
    /// This corresponds to [`SSL_CTX_set_verify_depth`].
    ///
    /// [`SSL_CTX_set_verify_depth`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_verify_depth.html
    pub fn set_verify_depth(&mut self, depth: u32) {
        unsafe {
            ffi::SSL_CTX_set_verify_depth(self.as_ptr(), depth as c_int);
        }
    }

    /// Sets a custom certificate store for verifying peer certificates.
    ///
    /// This corresponds to [`SSL_CTX_set0_verify_cert_store`].
    ///
    /// [`SSL_CTX_set0_verify_cert_store`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set0_verify_cert_store.html
    pub fn set_verify_cert_store(&mut self, cert_store: X509Store) -> Result<(), ErrorStack> {
        unsafe {
            let ptr = cert_store.as_ptr();
            cvt(ffi::SSL_CTX_set0_verify_cert_store(self.as_ptr(), ptr) as c_int)?;
            mem::forget(cert_store);

            Ok(())
        }
    }

    /// Replaces the context's certificate store.
    ///
    /// This corresponds to [`SSL_CTX_set_cert_store`].
    ///
    /// [`SSL_CTX_set_cert_store`]: https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_cert_store.html
    pub fn set_cert_store(&mut self, cert_store: X509Store) {
        unsafe {
            ffi::SSL_CTX_set_cert_store(self.as_ptr(), cert_store.as_ptr());
            mem::forget(cert_store);
        }
    }

    /// Controls read ahead behavior.
    ///
    /// If enabled, OpenSSL will read as much data as is available from the underlying stream,
    /// instead of a single record at a time.
    ///
    /// It has no effect when used with DTLS.
    ///
    /// This corresponds to [`SSL_CTX_set_read_ahead`].
    ///
    /// [`SSL_CTX_set_read_ahead`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_read_ahead.html
    pub fn set_read_ahead(&mut self, read_ahead: bool) {
        unsafe {
            ffi::SSL_CTX_set_read_ahead(self.as_ptr(), read_ahead as c_int);
        }
    }

    /// Sets the mode used by the context, returning the previous mode.
    ///
    /// This corresponds to [`SSL_CTX_set_mode`].
    ///
    /// [`SSL_CTX_set_mode`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_mode.html
    pub fn set_mode(&mut self, mode: SslMode) -> SslMode {
        unsafe {
            let bits = ffi::SSL_CTX_set_mode(self.as_ptr(), mode.bits());
            SslMode { bits }
        }
    }

    /// Sets the parameters to be used during ephemeral Diffie-Hellman key exchange.
    ///
    /// This corresponds to [`SSL_CTX_set_tmp_dh`].
    ///
    /// [`SSL_CTX_set_tmp_dh`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_tmp_dh.html
    pub fn set_tmp_dh(&mut self, dh: &DhRef<Params>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_tmp_dh(self.as_ptr(), dh.as_ptr()) as c_int).map(|_| ()) }
    }

    /// Sets the parameters to be used during ephemeral elliptic curve Diffie-Hellman key exchange.
    ///
    /// This corresponds to `SSL_CTX_set_tmp_ecdh`.
    pub fn set_tmp_ecdh(&mut self, key: &EcKeyRef<Params>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_tmp_ecdh(self.as_ptr(), key.as_ptr()) as c_int).map(|_| ()) }
    }

    /// Use the default locations of trusted certificates for verification.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables
    /// if present, or defaults specified at OpenSSL build time otherwise.
    ///
    /// This corresponds to [`SSL_CTX_set_default_verify_paths`].
    ///
    /// [`SSL_CTX_set_default_verify_paths`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_default_verify_paths.html
    pub fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_set_default_verify_paths(self.as_ptr())).map(|_| ()) }
    }

    /// Loads trusted root certificates from a file.
    ///
    /// The file should contain a sequence of PEM-formatted CA certificates.
    ///
    /// This corresponds to [`SSL_CTX_load_verify_locations`].
    ///
    /// [`SSL_CTX_load_verify_locations`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_load_verify_locations.html
    pub fn set_ca_file<P: AsRef<Path>>(&mut self, file: P) -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_load_verify_locations(
                self.as_ptr(),
                file.as_ptr() as *const _,
                ptr::null(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the list of CA names sent to the client.
    ///
    /// The CA certificates must still be added to the trust root - they are not automatically set
    /// as trusted by this method.
    ///
    /// This corresponds to [`SSL_CTX_set_client_CA_list`].
    ///
    /// [`SSL_CTX_set_client_CA_list`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_client_CA_list.html
    pub fn set_client_ca_list(&mut self, list: Stack<X509Name>) {
        unsafe {
            ffi::SSL_CTX_set_client_CA_list(self.as_ptr(), list.as_ptr());
            mem::forget(list);
        }
    }

    /// Add the provided CA certificate to the list sent by the server to the client when
    /// requesting client-side TLS authentication.
    ///
    /// This corresponds to [`SSL_CTX_add_client_CA`].
    ///
    /// [`SSL_CTX_add_client_CA`]: https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_set_client_CA_list.html
    pub fn add_client_ca(&mut self, cacert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_add_client_CA(self.as_ptr(), cacert.as_ptr())).map(|_| ()) }
    }

    /// Set the context identifier for sessions.
    ///
    /// This value identifies the server's session cache to clients, telling them when they're
    /// able to reuse sessions. It should be set to a unique value per server, unless multiple
    /// servers share a session cache.
    ///
    /// This value should be set when using client certificates, or each request will fail its
    /// handshake and need to be restarted.
    ///
    /// This corresponds to [`SSL_CTX_set_session_id_context`].
    ///
    /// [`SSL_CTX_set_session_id_context`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_session_id_context.html
    pub fn set_session_id_context(&mut self, sid_ctx: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            assert!(sid_ctx.len() <= c_uint::max_value() as usize);
            cvt(ffi::SSL_CTX_set_session_id_context(
                self.as_ptr(),
                sid_ctx.as_ptr(),
                sid_ctx.len(),
            ))
            .map(|_| ())
        }
    }

    /// Loads a leaf certificate from a file.
    ///
    /// Only a single certificate will be loaded - use `add_extra_chain_cert` to add the remainder
    /// of the certificate chain, or `set_certificate_chain_file` to load the entire chain from a
    /// single file.
    ///
    /// This corresponds to [`SSL_CTX_use_certificate_file`].
    ///
    /// [`SSL_CTX_use_certificate_file`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_certificate_file.html
    pub fn set_certificate_file<P: AsRef<Path>>(
        &mut self,
        file: P,
        file_type: SslFiletype,
    ) -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_file(
                self.as_ptr(),
                file.as_ptr() as *const _,
                file_type.as_raw(),
            ))
            .map(|_| ())
        }
    }

    /// Loads a certificate chain from a file.
    ///
    /// The file should contain a sequence of PEM-formatted certificates, the first being the leaf
    /// certificate, and the remainder forming the chain of certificates up to and including the
    /// trusted root certificate.
    ///
    /// This corresponds to [`SSL_CTX_use_certificate_chain_file`].
    ///
    /// [`SSL_CTX_use_certificate_chain_file`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_certificate_file.html
    pub fn set_certificate_chain_file<P: AsRef<Path>>(
        &mut self,
        file: P,
    ) -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_certificate_chain_file(
                self.as_ptr(),
                file.as_ptr() as *const _,
            ))
            .map(|_| ())
        }
    }

    /// Sets the leaf certificate.
    ///
    /// Use `add_extra_chain_cert` to add the remainder of the certificate chain.
    ///
    /// This corresponds to [`SSL_CTX_use_certificate`].
    ///
    /// [`SSL_CTX_use_certificate`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_certificate_file.html
    pub fn set_certificate(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Appends a certificate to the certificate chain.
    ///
    /// This chain should contain all certificates necessary to go from the certificate specified by
    /// `set_certificate` to a trusted root.
    ///
    /// This corresponds to [`SSL_CTX_add_extra_chain_cert`].
    ///
    /// [`SSL_CTX_add_extra_chain_cert`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_add_extra_chain_cert.html
    pub fn add_extra_chain_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CTX_add_extra_chain_cert(self.as_ptr(), cert.as_ptr()) as c_int)?;
            mem::forget(cert);
            Ok(())
        }
    }

    /// Loads the private key from a file.
    ///
    /// This corresponds to [`SSL_CTX_use_PrivateKey_file`].
    ///
    /// [`SSL_CTX_use_PrivateKey_file`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_PrivateKey_file.html
    pub fn set_private_key_file<P: AsRef<Path>>(
        &mut self,
        file: P,
        file_type: SslFiletype,
    ) -> Result<(), ErrorStack> {
        let file = CString::new(file.as_ref().as_os_str().to_str().unwrap()).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_use_PrivateKey_file(
                self.as_ptr(),
                file.as_ptr() as *const _,
                file_type.as_raw(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the private key.
    ///
    /// This corresponds to [`SSL_CTX_use_PrivateKey`].
    ///
    /// [`SSL_CTX_use_PrivateKey`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_use_PrivateKey_file.html
    pub fn set_private_key<T>(&mut self, key: &PKeyRef<T>) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe { cvt(ffi::SSL_CTX_use_PrivateKey(self.as_ptr(), key.as_ptr())).map(|_| ()) }
    }

    /// Sets the list of supported ciphers for protocols before TLSv1.3.
    ///
    /// The `set_ciphersuites` method controls the cipher suites for TLSv1.3.
    ///
    /// See [`ciphers`] for details on the format.
    ///
    /// This corresponds to [`SSL_CTX_set_cipher_list`].
    ///
    /// [`ciphers`]: https://www.openssl.org/docs/man1.1.0/apps/ciphers.html
    /// [`SSL_CTX_set_cipher_list`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_cipher_list.html
    pub fn set_cipher_list(&mut self, cipher_list: &str) -> Result<(), ErrorStack> {
        let cipher_list = CString::new(cipher_list).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_set_cipher_list(
                self.as_ptr(),
                cipher_list.as_ptr() as *const _,
            ))
            .map(|_| ())
        }
    }

    /// Sets the options used by the context, returning the old set.
    ///
    /// This corresponds to [`SSL_CTX_set_options`].
    ///
    /// # Note
    ///
    /// This *enables* the specified options, but does not disable unspecified options. Use
    /// `clear_options` for that.
    ///
    /// [`SSL_CTX_set_options`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html
    pub fn set_options(&mut self, option: SslOptions) -> SslOptions {
        let bits = unsafe { ffi::SSL_CTX_set_options(self.as_ptr(), option.bits()) };
        SslOptions { bits }
    }

    /// Returns the options used by the context.
    ///
    /// This corresponds to [`SSL_CTX_get_options`].
    ///
    /// [`SSL_CTX_get_options`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html
    pub fn options(&self) -> SslOptions {
        let bits = unsafe { ffi::SSL_CTX_get_options(self.as_ptr()) };
        SslOptions { bits }
    }

    /// Clears the options used by the context, returning the old set.
    ///
    /// This corresponds to [`SSL_CTX_clear_options`].
    ///
    /// [`SSL_CTX_clear_options`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html
    pub fn clear_options(&mut self, option: SslOptions) -> SslOptions {
        let bits = unsafe { ffi::SSL_CTX_clear_options(self.as_ptr(), option.bits()) };
        SslOptions { bits }
    }

    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` will enable protocol versions down the the lowest version supported by
    /// OpenSSL.
    ///
    /// This corresponds to [`SSL_CTX_set_min_proto_version`].
    ///
    /// [`SSL_CTX_set_min_proto_version`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_min_proto_version.html
    pub fn set_min_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CTX_set_min_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
            .map(|_| ())
        }
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` will enable protocol versions down the the highest version supported by
    /// OpenSSL.
    ///
    /// This corresponds to [`SSL_CTX_set_max_proto_version`].
    ///
    /// [`SSL_CTX_set_max_proto_version`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_min_proto_version.html
    pub fn set_max_proto_version(&mut self, version: Option<SslVersion>) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_CTX_set_max_proto_version(
                self.as_ptr(),
                version.map_or(0, |v| v.0 as _),
            ))
            .map(|_| ())
        }
    }

    /// Gets the minimum supported protocol version.
    ///
    /// A value of `None` indicates that all versions down the the lowest version supported by
    /// OpenSSL are enabled.
    ///
    /// This corresponds to [`SSL_CTX_get_min_proto_version`].
    ///
    /// [`SSL_CTX_get_min_proto_version`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_min_proto_version.html
    pub fn min_proto_version(&mut self) -> Option<SslVersion> {
        unsafe {
            let r = ffi::SSL_CTX_get_min_proto_version(self.as_ptr());
            if r == 0 {
                None
            } else {
                Some(SslVersion(r))
            }
        }
    }

    /// Gets the maximum supported protocol version.
    ///
    /// A value of `None` indicates that all versions down the the highest version supported by
    /// OpenSSL are enabled.
    ///
    /// This corresponds to [`SSL_CTX_get_max_proto_version`].
    ///
    /// [`SSL_CTX_get_max_proto_version`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_min_proto_version.html
    pub fn max_proto_version(&mut self) -> Option<SslVersion> {
        unsafe {
            let r = ffi::SSL_CTX_get_max_proto_version(self.as_ptr());
            if r == 0 {
                None
            } else {
                Some(SslVersion(r))
            }
        }
    }

    /// Sets the protocols to sent to the server for Application Layer Protocol Negotiation (ALPN).
    ///
    /// The input must be in ALPN "wire format". It consists of a sequence of supported protocol
    /// names prefixed by their byte length. For example, the protocol list consisting of `spdy/1`
    /// and `http/1.1` is encoded as `b"\x06spdy/1\x08http/1.1"`. The protocols are ordered by
    /// preference.
    ///
    /// This corresponds to [`SSL_CTX_set_alpn_protos`].
    ///
    /// [`SSL_CTX_set_alpn_protos`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_alpn_protos.html
    pub fn set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            assert!(protocols.len() <= c_uint::max_value() as usize);
            let r = ffi::SSL_CTX_set_alpn_protos(
                self.as_ptr(),
                protocols.as_ptr(),
                protocols.len() as c_uint,
            );
            // fun fact, SSL_CTX_set_alpn_protos has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Enables the DTLS extension "use_srtp" as defined in RFC5764.
    ///
    /// This corresponds to [`SSL_CTX_set_tlsext_use_srtp`].
    ///
    /// [`SSL_CTX_set_tlsext_use_srtp`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn set_tlsext_use_srtp(&mut self, protocols: &str) -> Result<(), ErrorStack> {
        unsafe {
            let cstr = CString::new(protocols).unwrap();

            let r = ffi::SSL_CTX_set_tlsext_use_srtp(self.as_ptr(), cstr.as_ptr());
            // fun fact, set_tlsext_use_srtp has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Sets the callback used by a server to select a protocol for Application Layer Protocol
    /// Negotiation (ALPN).
    ///
    /// The callback is provided with the client's protocol list in ALPN wire format. See the
    /// documentation for [`SslContextBuilder::set_alpn_protos`] for details. It should return one
    /// of those protocols on success. The [`select_next_proto`] function implements the standard
    /// protocol selection algorithm.
    ///
    /// This corresponds to [`SSL_CTX_set_alpn_select_cb`].
    ///
    /// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
    /// [`select_next_proto`]: fn.select_next_proto.html
    /// [`SSL_CTX_set_alpn_select_cb`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_alpn_protos.html
    pub fn set_alpn_select_callback<F>(&mut self, callback: F)
    where
        F: for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError> + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_alpn_select_cb(
                self.as_ptr(),
                Some(callbacks::raw_alpn_select::<F>),
                ptr::null_mut(),
            );
        }
    }
    /// Sets a callback that is called before most ClientHello processing and before the decision whether
    /// to resume a session is made. The callback may inspect the ClientHello and configure the
    /// connection.
    ///
    /// This corresponds to [`SSL_CTX_set_select_certificate_cb`].
    ///
    /// [`SSL_CTX_set_select_certificate_cb`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_select_certificate_cb.html
    pub fn set_select_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&ClientHello) -> Result<(), SelectCertError> + Sync + Send + 'static,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_select_certificate_cb(
                self.as_ptr(),
                Some(callbacks::raw_select_cert::<F>),
            );
        }
    }

    /// Checks for consistency between the private key and certificate.
    ///
    /// This corresponds to [`SSL_CTX_check_private_key`].
    ///
    /// [`SSL_CTX_check_private_key`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_check_private_key.html
    pub fn check_private_key(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_CTX_check_private_key(self.as_ptr())).map(|_| ()) }
    }

    /// Returns a shared reference to the context's certificate store.
    ///
    /// This corresponds to [`SSL_CTX_get_cert_store`].
    ///
    /// [`SSL_CTX_get_cert_store`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_get_cert_store.html
    pub fn cert_store(&self) -> &X509StoreBuilderRef {
        unsafe { X509StoreBuilderRef::from_ptr(ffi::SSL_CTX_get_cert_store(self.as_ptr())) }
    }

    /// Returns a mutable reference to the context's certificate store.
    ///
    /// This corresponds to [`SSL_CTX_get_cert_store`].
    ///
    /// [`SSL_CTX_get_cert_store`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_get_cert_store.html
    pub fn cert_store_mut(&mut self) -> &mut X509StoreBuilderRef {
        unsafe { X509StoreBuilderRef::from_ptr_mut(ffi::SSL_CTX_get_cert_store(self.as_ptr())) }
    }

    /// Sets the callback dealing with OCSP stapling.
    ///
    /// On the client side, this callback is responsible for validating the OCSP status response
    /// returned by the server. The status may be retrieved with the `SslRef::ocsp_status` method.
    /// A response of `Ok(true)` indicates that the OCSP status is valid, and a response of
    /// `Ok(false)` indicates that the OCSP status is invalid and the handshake should be
    /// terminated.
    ///
    /// On the server side, this callback is resopnsible for setting the OCSP status response to be
    /// returned to clients. The status may be set with the `SslRef::set_ocsp_status` method. A
    /// response of `Ok(true)` indicates that the OCSP status should be returned to the client, and
    /// `Ok(false)` indicates that the status should not be returned to the client.
    ///
    /// This corresponds to [`SSL_CTX_set_tlsext_status_cb`].
    ///
    /// [`SSL_CTX_set_tlsext_status_cb`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_tlsext_status_cb.html
    pub fn set_status_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&mut SslRef) -> Result<bool, ErrorStack> + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            cvt(
                ffi::SSL_CTX_set_tlsext_status_cb(self.as_ptr(), Some(raw_tlsext_status::<F>))
                    as c_int,
            )
            .map(|_| ())
        }
    }

    /// Sets the callback for providing an identity and pre-shared key for a TLS-PSK client.
    ///
    /// The callback will be called with the SSL context, an identity hint if one was provided
    /// by the server, a mutable slice for each of the identity and pre-shared key bytes. The
    /// identity must be written as a null-terminated C string.
    ///
    /// This corresponds to [`SSL_CTX_set_psk_client_callback`].
    ///
    /// [`SSL_CTX_set_psk_client_callback`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_psk_client_callback.html
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    pub fn set_psk_client_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_psk_client_callback(self.as_ptr(), Some(raw_client_psk::<F>));
        }
    }

    #[deprecated(since = "0.10.10", note = "renamed to `set_psk_client_callback`")]
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    pub fn set_psk_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8], &mut [u8]) -> Result<usize, ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        self.set_psk_client_callback(callback)
    }

    /// Sets the callback for providing an identity and pre-shared key for a TLS-PSK server.
    ///
    /// The callback will be called with the SSL context, an identity provided by the client,
    /// and, a mutable slice for the pre-shared key bytes. The callback returns the number of
    /// bytes in the pre-shared key.
    ///
    /// This corresponds to [`SSL_CTX_set_psk_server_callback`].
    ///
    /// [`SSL_CTX_set_psk_server_callback`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_psk_server_callback.html
    #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
    pub fn set_psk_server_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, Option<&[u8]>, &mut [u8]) -> Result<usize, ErrorStack>
            + 'static
            + Sync
            + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_psk_server_callback(self.as_ptr(), Some(raw_server_psk::<F>));
        }
    }

    /// Sets the callback which is called when new sessions are negotiated.
    ///
    /// This can be used by clients to implement session caching. While in TLSv1.2 the session is
    /// available to access via [`SslRef::session`] immediately after the handshake completes, this
    /// is not the case for TLSv1.3. There, a session is not generally available immediately, and
    /// the server may provide multiple session tokens to the client over a single session. The new
    /// session callback is a portable way to deal with both cases.
    ///
    /// Note that session caching must be enabled for the callback to be invoked, and it defaults
    /// off for clients. [`set_session_cache_mode`] controls that behavior.
    ///
    /// This corresponds to [`SSL_CTX_sess_set_new_cb`].
    ///
    /// [`SslRef::session`]: struct.SslRef.html#method.session
    /// [`set_session_cache_mode`]: #method.set_session_cache_mode
    /// [`SSL_CTX_sess_set_new_cb`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_sess_set_new_cb.html
    pub fn set_new_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, SslSession) + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), Some(callbacks::raw_new_session::<F>));
        }
    }

    /// Sets the callback which is called when sessions are removed from the context.
    ///
    /// Sessions can be removed because they have timed out or because they are considered faulty.
    ///
    /// This corresponds to [`SSL_CTX_sess_set_remove_cb`].
    ///
    /// [`SSL_CTX_sess_set_remove_cb`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_sess_set_new_cb.html
    pub fn set_remove_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SslContextRef, &SslSessionRef) + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_sess_set_remove_cb(
                self.as_ptr(),
                Some(callbacks::raw_remove_session::<F>),
            );
        }
    }

    /// Sets the callback which is called when a client proposed to resume a session but it was not
    /// found in the internal cache.
    ///
    /// The callback is passed a reference to the session ID provided by the client. It should
    /// return the session corresponding to that ID if available. This is only used for servers, not
    /// clients.
    ///
    /// This corresponds to [`SSL_CTX_sess_set_get_cb`].
    ///
    /// # Safety
    ///
    /// The returned `SslSession` must not be associated with a different `SslContext`.
    ///
    /// [`SSL_CTX_sess_set_get_cb`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_sess_set_new_cb.html
    pub unsafe fn set_get_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &[u8]) -> Option<SslSession> + 'static + Sync + Send,
    {
        self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
        ffi::SSL_CTX_sess_set_get_cb(self.as_ptr(), Some(callbacks::raw_get_session::<F>));
    }

    /// Sets the TLS key logging callback.
    ///
    /// The callback is invoked whenever TLS key material is generated, and is passed a line of NSS
    /// SSLKEYLOGFILE-formatted text. This can be used by tools like Wireshark to decrypt message
    /// traffic. The line does not contain a trailing newline.
    ///
    /// This corresponds to [`SSL_CTX_set_keylog_callback`].
    ///
    /// [`SSL_CTX_set_keylog_callback`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_keylog_callback.html
    pub fn set_keylog_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SslRef, &str) + 'static + Sync + Send,
    {
        unsafe {
            self.set_ex_data(SslContext::cached_ex_index::<F>(), callback);
            ffi::SSL_CTX_set_keylog_callback(self.as_ptr(), Some(callbacks::raw_keylog::<F>));
        }
    }

    /// Sets the session caching mode use for connections made with the context.
    ///
    /// Returns the previous session caching mode.
    ///
    /// This corresponds to [`SSL_CTX_set_session_cache_mode`].
    ///
    /// [`SSL_CTX_set_session_cache_mode`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_get_session_cache_mode.html
    pub fn set_session_cache_mode(&mut self, mode: SslSessionCacheMode) -> SslSessionCacheMode {
        unsafe {
            let bits = ffi::SSL_CTX_set_session_cache_mode(self.as_ptr(), mode.bits());
            SslSessionCacheMode { bits }
        }
    }

    /// Sets the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `SslContext::new_ex_index` method to create an `Index`.
    ///
    /// This corresponds to [`SSL_CTX_set_ex_data`].
    ///
    /// [`SSL_CTX_set_ex_data`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_ex_data.html
    pub fn set_ex_data<T>(&mut self, index: Index<SslContext, T>, data: T) {
        self.set_ex_data_inner(index, data);
    }

    fn set_ex_data_inner<T>(&mut self, index: Index<SslContext, T>, data: T) -> *mut c_void {
        unsafe {
            let data = Box::into_raw(Box::new(data)) as *mut c_void;
            ffi::SSL_CTX_set_ex_data(self.as_ptr(), index.as_raw(), data);
            data
        }
    }

    /// Sets the context's session cache size limit, returning the previous limit.
    ///
    /// A value of 0 means that the cache size is unbounded.
    ///
    /// This corresponds to [`SSL_CTX_sess_get_cache_size`].
    ///
    /// [`SSL_CTX_sess_get_cache_size`]: https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_sess_set_cache_size.html
    #[allow(clippy::useless_conversion)]
    pub fn set_session_cache_size(&mut self, size: u32) -> u64 {
        unsafe { ffi::SSL_CTX_sess_set_cache_size(self.as_ptr(), size.into()).into() }
    }

    /// Sets the context's supported signature algorithms.
    ///
    /// This corresponds to [`SSL_CTX_set1_sigalgs_list`].
    ///
    /// [`SSL_CTX_set1_sigalgs_list`]: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set1_sigalgs_list.html
    pub fn set_sigalgs_list(&mut self, sigalgs: &str) -> Result<(), ErrorStack> {
        let sigalgs = CString::new(sigalgs).unwrap();
        unsafe {
            cvt(ffi::SSL_CTX_set1_sigalgs_list(self.as_ptr(), sigalgs.as_ptr()) as c_int)
                .map(|_| ())
        }
    }

    /// Set's whether the context should enable GREASE.
    ///
    /// This corresponds to [`SSL_CTX_set_grease_enabled`]
    ///
    /// [`SSL_CTX_set_grease_enabled`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_grease_enabled
    pub fn set_grease_enabled(&mut self, enabled: bool) {
        unsafe { ffi::SSL_CTX_set_grease_enabled(self.as_ptr(), enabled as _) }
    }

    /// Sets the context's supported signature verification algorithms.
    ///
    /// This corresponds to [`SSL_CTX_set_verify_algorithm_prefs`]
    ///
    /// [`SSL_CTX_set_verify_algorithm_prefs`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_verify_algorithm_prefs
    pub fn set_verify_algorithm_prefs(
        &mut self,
        prefs: &[SslSignatureAlgorithm],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_CTX_set_verify_algorithm_prefs(
                self.as_ptr(),
                prefs.as_ptr() as *const _,
                prefs.len(),
            ))
            .map(|_| ())
        }
    }

    /// Enables SCT requests on all client SSL handshakes.
    ///
    /// This corresponds to [`SSL_CTX_enable_signed_cert_timestamps`]
    ///
    /// [`SSL_CTX_enable_signed_cert_timestamps`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_enable_signed_cert_timestamps
    pub fn enable_signed_cert_timestamps(&mut self) {
        unsafe { ffi::SSL_CTX_enable_signed_cert_timestamps(self.as_ptr()) }
    }

    /// Enables OCSP stapling on all client SSL handshakes.
    ///
    /// This corresponds to [`SSL_CTX_enable_ocsp_stapling`]
    ///
    /// [`SSL_CTX_enable_ocsp_stapling`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_enable_ocsp_stapling
    pub fn enable_ocsp_stapling(&mut self) {
        unsafe { ffi::SSL_CTX_enable_ocsp_stapling(self.as_ptr()) }
    }

    /// Sets the context's supported curves.
    ///
    /// This corresponds to [`SSL_CTX_set1_curves`]
    ///
    /// [`SSL_CTX_set1_curves`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set1_curves
    pub fn set_curves(&mut self, curves: &[SslCurve]) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_CTX_set1_curves(
                self.as_ptr(),
                curves.as_ptr() as *const _,
                curves.len(),
            ))
            .map(|_| ())
        }
    }

    /// Consumes the builder, returning a new `SslContext`.
    pub fn build(self) -> SslContext {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CTX;
    fn drop = ffi::SSL_CTX_free;

    /// A context object for TLS streams.
    ///
    /// Applications commonly configure a single `SslContext` that is shared by all of its
    /// `SslStreams`.
    pub struct SslContext;

    /// Reference to [`SslContext`]
    ///
    /// [`SslContext`]: struct.SslContext.html
    pub struct SslContextRef;
}

impl Clone for SslContext {
    fn clone(&self) -> Self {
        unsafe {
            SSL_CTX_up_ref(self.as_ptr());
            SslContext::from_ptr(self.as_ptr())
        }
    }
}

// TODO: add useful info here
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SslContext")
    }
}

impl SslContext {
    /// Creates a new builder object for an `SslContext`.
    pub fn builder(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        SslContextBuilder::new(method)
    }

    /// Returns a new extra data index.
    ///
    /// Each invocation of this function is guaranteed to return a distinct index. These can be used
    /// to store data in the context that can be retrieved later by callbacks, for example.
    ///
    /// This corresponds to [`SSL_CTX_get_ex_new_index`].
    ///
    /// [`SSL_CTX_get_ex_new_index`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_get_ex_new_index.html
    pub fn new_ex_index<T>() -> Result<Index<SslContext, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }

    // FIXME should return a result?
    fn cached_ex_index<T>() -> Index<SslContext, T>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = *INDEXES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(TypeId::of::<T>())
                .or_insert_with(|| SslContext::new_ex_index::<T>().unwrap().as_raw());
            Index::from_raw(idx)
        }
    }
}

impl SslContextRef {
    /// Returns the certificate associated with this `SslContext`, if present.
    ///
    /// This corresponds to [`SSL_CTX_get0_certificate`].
    ///
    /// [`SSL_CTX_get0_certificate`]: https://www.openssl.org/docs/man1.1.0/ssl/ssl.html
    pub fn certificate(&self) -> Option<&X509Ref> {
        unsafe {
            let ptr = ffi::SSL_CTX_get0_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Returns the private key associated with this `SslContext`, if present.
    ///
    /// This corresponds to [`SSL_CTX_get0_privatekey`].
    ///
    /// [`SSL_CTX_get0_privatekey`]: https://www.openssl.org/docs/man1.1.0/ssl/ssl.html
    pub fn private_key(&self) -> Option<&PKeyRef<Private>> {
        unsafe {
            let ptr = ffi::SSL_CTX_get0_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }

    /// Returns a shared reference to the certificate store used for verification.
    ///
    /// This corresponds to [`SSL_CTX_get_cert_store`].
    ///
    /// [`SSL_CTX_get_cert_store`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_get_cert_store.html
    pub fn cert_store(&self) -> &X509StoreRef {
        unsafe { X509StoreRef::from_ptr(ffi::SSL_CTX_get_cert_store(self.as_ptr())) }
    }

    /// Returns a shared reference to the stack of certificates making up the chain from the leaf.
    ///
    /// This corresponds to `SSL_CTX_get_extra_chain_certs`.
    pub fn extra_chain_certs(&self) -> &StackRef<X509> {
        unsafe {
            let mut chain = ptr::null_mut();
            ffi::SSL_CTX_get_extra_chain_certs(self.as_ptr(), &mut chain);
            assert!(!chain.is_null());
            StackRef::from_ptr(chain)
        }
    }

    /// Returns a reference to the extra data at the specified index.
    ///
    /// This corresponds to [`SSL_CTX_get_ex_data`].
    ///
    /// [`SSL_CTX_get_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_get_ex_data.html
    pub fn ex_data<T>(&self, index: Index<SslContext, T>) -> Option<&T> {
        unsafe {
            let data = ffi::SSL_CTX_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    /// Adds a session to the context's cache.
    ///
    /// Returns `true` if the session was successfully added to the cache, and `false` if it was already present.
    ///
    /// This corresponds to [`SSL_CTX_add_session`].
    ///
    /// # Safety
    ///
    /// The caller of this method is responsible for ensuring that the session has never been used with another
    /// `SslContext` than this one.
    ///
    /// [`SSL_CTX_add_session`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_remove_session.html
    pub unsafe fn add_session(&self, session: &SslSessionRef) -> bool {
        ffi::SSL_CTX_add_session(self.as_ptr(), session.as_ptr()) != 0
    }

    /// Removes a session from the context's cache and marks it as non-resumable.
    ///
    /// Returns `true` if the session was successfully found and removed, and `false` otherwise.
    ///
    /// This corresponds to [`SSL_CTX_remove_session`].
    ///
    /// # Safety
    ///
    /// The caller of this method is responsible for ensuring that the session has never been used with another
    /// `SslContext` than this one.
    ///
    /// [`SSL_CTX_remove_session`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_remove_session.html
    pub unsafe fn remove_session(&self, session: &SslSessionRef) -> bool {
        ffi::SSL_CTX_remove_session(self.as_ptr(), session.as_ptr()) != 0
    }

    /// Returns the context's session cache size limit.
    ///
    /// A value of 0 means that the cache size is unbounded.
    ///
    /// This corresponds to [`SSL_CTX_sess_get_cache_size`].
    ///
    /// [`SSL_CTX_sess_get_cache_size`]: https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_sess_set_cache_size.html
    #[allow(clippy::useless_conversion)]
    pub fn session_cache_size(&self) -> u64 {
        unsafe { ffi::SSL_CTX_sess_get_cache_size(self.as_ptr()).into() }
    }

    /// Returns the verify mode that was set on this context from [`SslContextBuilder::set_verify`].
    ///
    /// This corresponds to [`SSL_CTX_get_verify_mode`].
    ///
    /// [`SslContextBuilder::set_verify`]: struct.SslContextBuilder.html#method.set_verify
    /// [`SSL_CTX_get_verify_mode`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_get_verify_mode.html
    pub fn verify_mode(&self) -> SslVerifyMode {
        let mode = unsafe { ffi::SSL_CTX_get_verify_mode(self.as_ptr()) };
        SslVerifyMode::from_bits(mode).expect("SSL_CTX_get_verify_mode returned invalid mode")
    }
}

/// Information about the state of a cipher.
pub struct CipherBits {
    /// The number of secret bits used for the cipher.
    pub secret: i32,

    /// The number of bits processed by the chosen algorithm.
    pub algorithm: i32,
}

#[repr(transparent)]
pub struct ClientHello(ffi::SSL_CLIENT_HELLO);

impl ClientHello {
    /// Returns the data of a given extension, if present.
    ///
    /// This corresponds to [`SSL_early_callback_ctx_extension_get`].
    ///
    /// [`SSL_early_callback_ctx_extension_get`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_early_callback_ctx_extension_get
    pub fn get_extension(&self, ext_type: ExtensionType) -> Option<&[u8]> {
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            let result =
                ffi::SSL_early_callback_ctx_extension_get(&self.0, ext_type.0, &mut ptr, &mut len);
            if result == 0 {
                return None;
            }
            Some(slice::from_raw_parts(ptr, len))
        }
    }
}

/// Information about a cipher.
pub struct SslCipher(*mut ffi::SSL_CIPHER);

impl ForeignType for SslCipher {
    type CType = ffi::SSL_CIPHER;
    type Ref = SslCipherRef;

    #[inline]
    unsafe fn from_ptr(ptr: *mut ffi::SSL_CIPHER) -> SslCipher {
        SslCipher(ptr)
    }

    #[inline]
    fn as_ptr(&self) -> *mut ffi::SSL_CIPHER {
        self.0
    }
}

impl Deref for SslCipher {
    type Target = SslCipherRef;

    fn deref(&self) -> &SslCipherRef {
        unsafe { SslCipherRef::from_ptr(self.0) }
    }
}

impl DerefMut for SslCipher {
    fn deref_mut(&mut self) -> &mut SslCipherRef {
        unsafe { SslCipherRef::from_ptr_mut(self.0) }
    }
}

/// Reference to an [`SslCipher`].
///
/// [`SslCipher`]: struct.SslCipher.html
pub struct SslCipherRef(Opaque);

impl ForeignTypeRef for SslCipherRef {
    type CType = ffi::SSL_CIPHER;
}

impl SslCipherRef {
    /// Returns the name of the cipher.
    ///
    /// This corresponds to [`SSL_CIPHER_get_name`].
    ///
    /// [`SSL_CIPHER_get_name`]: https://www.openssl.org/docs/manmaster/man3/SSL_CIPHER_get_name.html
    pub fn name(&self) -> &'static str {
        unsafe {
            let ptr = ffi::SSL_CIPHER_get_name(self.as_ptr());
            CStr::from_ptr(ptr).to_str().unwrap()
        }
    }

    /// Returns the RFC-standard name of the cipher, if one exists.
    ///
    /// This corresponds to [`SSL_CIPHER_standard_name`].
    ///
    /// [`SSL_CIPHER_standard_name`]: https://www.openssl.org/docs/manmaster/man3/SSL_CIPHER_get_name.html
    pub fn standard_name(&self) -> Option<&'static str> {
        unsafe {
            let ptr = ffi::SSL_CIPHER_standard_name(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(ptr).to_str().unwrap())
            }
        }
    }

    /// Returns the SSL/TLS protocol version that first defined the cipher.
    ///
    /// This corresponds to [`SSL_CIPHER_get_version`].
    ///
    /// [`SSL_CIPHER_get_version`]: https://www.openssl.org/docs/manmaster/man3/SSL_CIPHER_get_name.html
    pub fn version(&self) -> &'static str {
        let version = unsafe {
            let ptr = ffi::SSL_CIPHER_get_version(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
    }

    /// Returns the number of bits used for the cipher.
    ///
    /// This corresponds to [`SSL_CIPHER_get_bits`].
    ///
    /// [`SSL_CIPHER_get_bits`]: https://www.openssl.org/docs/manmaster/man3/SSL_CIPHER_get_name.html
    #[allow(clippy::useless_conversion)]
    pub fn bits(&self) -> CipherBits {
        unsafe {
            let mut algo_bits = 0;
            let secret_bits = ffi::SSL_CIPHER_get_bits(self.as_ptr(), &mut algo_bits);
            CipherBits {
                secret: secret_bits.into(),
                algorithm: algo_bits.into(),
            }
        }
    }

    /// Returns a textual description of the cipher.
    ///
    /// This corresponds to [`SSL_CIPHER_description`].
    ///
    /// [`SSL_CIPHER_description`]: https://www.openssl.org/docs/manmaster/man3/SSL_CIPHER_get_name.html
    pub fn description(&self) -> String {
        unsafe {
            // SSL_CIPHER_description requires a buffer of at least 128 bytes.
            let mut buf = [0; 128];
            let ptr = ffi::SSL_CIPHER_description(self.as_ptr(), buf.as_mut_ptr(), 128);
            String::from_utf8(CStr::from_ptr(ptr as *const _).to_bytes().to_vec()).unwrap()
        }
    }

    /// Returns the NID corresponding to the cipher.
    ///
    /// This corresponds to [`SSL_CIPHER_get_cipher_nid`].
    ///
    /// [`SSL_CIPHER_get_cipher_nid`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_CIPHER_get_cipher_nid.html
    pub fn cipher_nid(&self) -> Option<Nid> {
        let n = unsafe { ffi::SSL_CIPHER_get_cipher_nid(self.as_ptr()) };
        if n == 0 {
            None
        } else {
            Some(Nid::from_raw(n))
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_SESSION;
    fn drop = ffi::SSL_SESSION_free;

    /// An encoded SSL session.
    ///
    /// These can be cached to share sessions across connections.
    pub struct SslSession;

    /// Reference to [`SslSession`].
    ///
    /// [`SslSession`]: struct.SslSession.html
    pub struct SslSessionRef;
}

impl Clone for SslSession {
    fn clone(&self) -> SslSession {
        SslSessionRef::to_owned(self)
    }
}

impl SslSession {
    from_der! {
        /// Deserializes a DER-encoded session structure.
        ///
        /// This corresponds to [`d2i_SSL_SESSION`].
        ///
        /// [`d2i_SSL_SESSION`]: https://www.openssl.org/docs/man1.0.2/ssl/d2i_SSL_SESSION.html
        from_der,
        SslSession,
        ffi::d2i_SSL_SESSION,
        ::libc::c_long
    }
}

impl ToOwned for SslSessionRef {
    type Owned = SslSession;

    fn to_owned(&self) -> SslSession {
        unsafe {
            SSL_SESSION_up_ref(self.as_ptr());
            SslSession(self.as_ptr())
        }
    }
}

impl SslSessionRef {
    /// Returns the SSL session ID.
    ///
    /// This corresponds to [`SSL_SESSION_get_id`].
    ///
    /// [`SSL_SESSION_get_id`]: https://www.openssl.org/docs/manmaster/man3/SSL_SESSION_get_id.html
    pub fn id(&self) -> &[u8] {
        unsafe {
            let mut len = 0;
            let p = ffi::SSL_SESSION_get_id(self.as_ptr(), &mut len);
            slice::from_raw_parts(p as *const u8, len as usize)
        }
    }

    /// Returns the length of the master key.
    ///
    /// This corresponds to [`SSL_SESSION_get_master_key`].
    ///
    /// [`SSL_SESSION_get_master_key`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_SESSION_get_master_key.html
    pub fn master_key_len(&self) -> usize {
        unsafe { SSL_SESSION_get_master_key(self.as_ptr(), ptr::null_mut(), 0) }
    }

    /// Copies the master key into the provided buffer.
    ///
    /// Returns the number of bytes written, or the size of the master key if the buffer is empty.
    ///
    /// This corresponds to [`SSL_SESSION_get_master_key`].
    ///
    /// [`SSL_SESSION_get_master_key`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_SESSION_get_master_key.html
    pub fn master_key(&self, buf: &mut [u8]) -> usize {
        unsafe { SSL_SESSION_get_master_key(self.as_ptr(), buf.as_mut_ptr(), buf.len()) }
    }

    /// Returns the time at which the session was established, in seconds since the Unix epoch.
    ///
    /// This corresponds to [`SSL_SESSION_get_time`].
    ///
    /// [`SSL_SESSION_get_time`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_SESSION_get_time.html
    #[allow(clippy::useless_conversion)]
    pub fn time(&self) -> u64 {
        unsafe { ffi::SSL_SESSION_get_time(self.as_ptr()) }
    }

    /// Returns the sessions timeout, in seconds.
    ///
    /// A session older than this time should not be used for session resumption.
    ///
    /// This corresponds to [`SSL_SESSION_get_timeout`].
    ///
    /// [`SSL_SESSION_get_timeout`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_SESSION_get_time.html
    #[allow(clippy::useless_conversion)]
    pub fn timeout(&self) -> u32 {
        unsafe { ffi::SSL_SESSION_get_timeout(self.as_ptr()) }
    }

    /// Returns the session's TLS protocol version.
    ///
    /// This corresponds to [`SSL_SESSION_get_protocol_version`].
    ///
    /// [`SSL_SESSION_get_protocol_version`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_SESSION_get_protocol_version.html
    pub fn protocol_version(&self) -> SslVersion {
        unsafe {
            let version = ffi::SSL_SESSION_get_protocol_version(self.as_ptr());
            SslVersion(version)
        }
    }

    to_der! {
        /// Serializes the session into a DER-encoded structure.
        ///
        /// This corresponds to [`i2d_SSL_SESSION`].
        ///
        /// [`i2d_SSL_SESSION`]: https://www.openssl.org/docs/man1.0.2/ssl/i2d_SSL_SESSION.html
        to_der,
        ffi::i2d_SSL_SESSION
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL;
    fn drop = ffi::SSL_free;

    /// The state of an SSL/TLS session.
    ///
    /// `Ssl` objects are created from an [`SslContext`], which provides configuration defaults.
    /// These defaults can be overridden on a per-`Ssl` basis, however.
    ///
    /// [`SslContext`]: struct.SslContext.html
    pub struct Ssl;

    /// Reference to an [`Ssl`].
    ///
    /// [`Ssl`]: struct.Ssl.html
    pub struct SslRef;
}

impl fmt::Debug for Ssl {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

impl Ssl {
    /// Returns a new extra data index.
    ///
    /// Each invocation of this function is guaranteed to return a distinct index. These can be used
    /// to store data in the context that can be retrieved later by callbacks, for example.
    ///
    /// This corresponds to [`SSL_get_ex_new_index`].
    ///
    /// [`SSL_get_ex_new_index`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_get_ex_new_index.html
    pub fn new_ex_index<T>() -> Result<Index<Ssl, T>, ErrorStack>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            ffi::init();
            let idx = cvt_n(get_new_ssl_idx(Some(free_data_box::<T>)))?;
            Ok(Index::from_raw(idx))
        }
    }

    // FIXME should return a result?
    fn cached_ex_index<T>() -> Index<Ssl, T>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = *SSL_INDEXES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(TypeId::of::<T>())
                .or_insert_with(|| Ssl::new_ex_index::<T>().unwrap().as_raw());
            Index::from_raw(idx)
        }
    }

    /// Creates a new `Ssl`.
    ///
    /// This corresponds to [`SSL_new`].
    ///
    /// [`SSL_new`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_new.html
    // FIXME should take &SslContextRef
    pub fn new(ctx: &SslContext) -> Result<Ssl, ErrorStack> {
        unsafe {
            let ptr = cvt_p(ffi::SSL_new(ctx.as_ptr()))?;
            let mut ssl = Ssl::from_ptr(ptr);
            ssl.set_ex_data(*SESSION_CTX_INDEX, ctx.clone());

            Ok(ssl)
        }
    }

    /// Initiates a client-side TLS handshake.
    ///
    /// This corresponds to [`SSL_connect`].
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// `SslConnector` rather than `Ssl` directly, as it manages that configuration.
    ///
    /// [`SSL_connect`]: https://www.openssl.org/docs/manmaster/man3/SSL_connect.html
    pub fn connect<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        SslStreamBuilder::new(self, stream).connect()
    }

    /// Initiates a server-side TLS handshake.
    ///
    /// This corresponds to [`SSL_accept`].
    ///
    /// # Warning
    ///
    /// OpenSSL's default configuration is insecure. It is highly recommended to use
    /// `SslAcceptor` rather than `Ssl` directly, as it manages that configuration.
    ///
    /// [`SSL_accept`]: https://www.openssl.org/docs/manmaster/man3/SSL_accept.html
    pub fn accept<S>(self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        SslStreamBuilder::new(self, stream).accept()
    }
}

impl fmt::Debug for SslRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Ssl")
            .field("state", &self.state_string_long())
            .field("verify_result", &self.verify_result())
            .finish()
    }
}

impl SslRef {
    fn get_raw_rbio(&self) -> *mut ffi::BIO {
        unsafe { ffi::SSL_get_rbio(self.as_ptr()) }
    }

    fn read(&mut self, buf: &mut [u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_read(self.as_ptr(), buf.as_ptr() as *mut c_void, len) }
    }

    fn write(&mut self, buf: &[u8]) -> c_int {
        let len = cmp::min(c_int::max_value() as usize, buf.len()) as c_int;
        unsafe { ffi::SSL_write(self.as_ptr(), buf.as_ptr() as *const c_void, len) }
    }

    fn get_error(&self, ret: c_int) -> ErrorCode {
        unsafe { ErrorCode::from_raw(ffi::SSL_get_error(self.as_ptr(), ret)) }
    }

    /// Like [`SslContextBuilder::set_verify`].
    ///
    /// This corresponds to [`SSL_set_verify`].
    ///
    /// [`SslContextBuilder::set_verify`]: struct.SslContextBuilder.html#method.set_verify
    /// [`SSL_set_verify`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_verify.html
    pub fn set_verify(&mut self, mode: SslVerifyMode) {
        unsafe { ffi::SSL_set_verify(self.as_ptr(), mode.bits as c_int, None) }
    }

    /// Returns the verify mode that was set using `set_verify`.
    ///
    /// This corresponds to [`SSL_get_verify_mode`].
    ///
    /// [`SSL_get_verify_mode`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_get_verify_mode.html
    pub fn verify_mode(&self) -> SslVerifyMode {
        let mode = unsafe { ffi::SSL_get_verify_mode(self.as_ptr()) };
        SslVerifyMode::from_bits(mode).expect("SSL_get_verify_mode returned invalid mode")
    }

    /// Like [`SslContextBuilder::set_verify_callback`].
    ///
    /// This corresponds to [`SSL_set_verify`].
    ///
    /// [`SslContextBuilder::set_verify_callback`]: struct.SslContextBuilder.html#method.set_verify_callback
    /// [`SSL_set_verify`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_verify.html
    pub fn set_verify_callback<F>(&mut self, mode: SslVerifyMode, verify: F)
    where
        F: Fn(bool, &mut X509StoreContextRef) -> bool + 'static + Sync + Send,
    {
        unsafe {
            // this needs to be in an Arc since the callback can register a new callback!
            self.set_ex_data(Ssl::cached_ex_index(), Arc::new(verify));
            ffi::SSL_set_verify(self.as_ptr(), mode.bits as c_int, Some(ssl_raw_verify::<F>));
        }
    }

    /// Like [`SslContextBuilder::set_tmp_dh`].
    ///
    /// This corresponds to [`SSL_set_tmp_dh`].
    ///
    /// [`SslContextBuilder::set_tmp_dh`]: struct.SslContextBuilder.html#method.set_tmp_dh
    /// [`SSL_set_tmp_dh`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tmp_dh.html
    pub fn set_tmp_dh(&mut self, dh: &DhRef<Params>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_set_tmp_dh(self.as_ptr(), dh.as_ptr()) as c_int).map(|_| ()) }
    }

    /// Like [`SslContextBuilder::set_tmp_ecdh`].
    ///
    /// This corresponds to `SSL_set_tmp_ecdh`.
    ///
    /// [`SslContextBuilder::set_tmp_ecdh`]: struct.SslContextBuilder.html#method.set_tmp_ecdh
    pub fn set_tmp_ecdh(&mut self, key: &EcKeyRef<Params>) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_set_tmp_ecdh(self.as_ptr(), key.as_ptr()) as c_int).map(|_| ()) }
    }

    /// Like [`SslContextBuilder::set_alpn_protos`].
    ///
    /// This corresponds to [`SSL_set_alpn_protos`].
    ///
    /// [`SslContextBuilder::set_alpn_protos`]: struct.SslContextBuilder.html#method.set_alpn_protos
    /// [`SSL_set_alpn_protos`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_alpn_protos.html
    pub fn set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            assert!(protocols.len() <= c_uint::max_value() as usize);
            let r = ffi::SSL_set_alpn_protos(
                self.as_ptr(),
                protocols.as_ptr(),
                protocols.len() as c_uint,
            );
            // fun fact, SSL_set_alpn_protos has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Returns the current cipher if the session is active.
    ///
    /// This corresponds to [`SSL_get_current_cipher`].
    ///
    /// [`SSL_get_current_cipher`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_current_cipher.html
    pub fn current_cipher(&self) -> Option<&SslCipherRef> {
        unsafe {
            let ptr = ffi::SSL_get_current_cipher(self.as_ptr());

            if ptr.is_null() {
                None
            } else {
                Some(SslCipherRef::from_ptr(ptr as *mut _))
            }
        }
    }

    /// Returns a short string describing the state of the session.
    ///
    /// This corresponds to [`SSL_state_string`].
    ///
    /// [`SSL_state_string`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_state_string.html
    pub fn state_string(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Returns a longer string describing the state of the session.
    ///
    /// This corresponds to [`SSL_state_string_long`].
    ///
    /// [`SSL_state_string_long`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_state_string_long.html
    pub fn state_string_long(&self) -> &'static str {
        let state = unsafe {
            let ptr = ffi::SSL_state_string_long(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(state.to_bytes()).unwrap()
    }

    /// Sets the host name to be sent to the server for Server Name Indication (SNI).
    ///
    /// It has no effect for a server-side connection.
    ///
    /// This corresponds to [`SSL_set_tlsext_host_name`].
    ///
    /// [`SSL_set_tlsext_host_name`]: https://www.openssl.org/docs/manmaster/man3/SSL_get_servername_type.html
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), ErrorStack> {
        let cstr = CString::new(hostname).unwrap();
        unsafe {
            cvt(ffi::SSL_set_tlsext_host_name(self.as_ptr(), cstr.as_ptr() as *mut _) as c_int)
                .map(|_| ())
        }
    }

    /// Returns the peer's certificate, if present.
    ///
    /// This corresponds to [`SSL_get_peer_certificate`].
    ///
    /// [`SSL_get_peer_certificate`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_peer_certificate.html
    pub fn peer_certificate(&self) -> Option<X509> {
        unsafe {
            let ptr = ffi::SSL_get_peer_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509::from_ptr(ptr))
            }
        }
    }

    /// Returns the certificate chain of the peer, if present.
    ///
    /// On the client side, the chain includes the leaf certificate, but on the server side it does
    /// not. Fun!
    ///
    /// This corresponds to [`SSL_get_peer_cert_chain`].
    ///
    /// [`SSL_get_peer_cert_chain`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_peer_cert_chain.html
    pub fn peer_cert_chain(&self) -> Option<&StackRef<X509>> {
        unsafe {
            let ptr = ffi::SSL_get_peer_cert_chain(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(ptr))
            }
        }
    }

    /// Like [`SslContext::certificate`].
    ///
    /// This corresponds to `SSL_get_certificate`.
    ///
    /// [`SslContext::certificate`]: struct.SslContext.html#method.certificate
    pub fn certificate(&self) -> Option<&X509Ref> {
        unsafe {
            let ptr = ffi::SSL_get_certificate(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(X509Ref::from_ptr(ptr))
            }
        }
    }

    /// Like [`SslContext::private_key`].
    ///
    /// This corresponds to `SSL_get_privatekey`.
    ///
    /// [`SslContext::private_key`]: struct.SslContext.html#method.private_key
    pub fn private_key(&self) -> Option<&PKeyRef<Private>> {
        unsafe {
            let ptr = ffi::SSL_get_privatekey(self.as_ptr());
            if ptr.is_null() {
                None
            } else {
                Some(PKeyRef::from_ptr(ptr))
            }
        }
    }

    #[deprecated(since = "0.10.5", note = "renamed to `version_str`")]
    pub fn version(&self) -> &str {
        self.version_str()
    }

    /// Returns the protocol version of the session.
    ///
    /// This corresponds to [`SSL_version`].
    ///
    /// [`SSL_version`]: https://www.openssl.org/docs/manmaster/man3/SSL_version.html
    pub fn version2(&self) -> Option<SslVersion> {
        unsafe {
            let r = ffi::SSL_version(self.as_ptr());
            if r == 0 {
                None
            } else {
                r.try_into().ok().map(SslVersion)
            }
        }
    }

    /// Returns a string describing the protocol version of the session.
    ///
    /// This corresponds to [`SSL_get_version`].
    ///
    /// [`SSL_get_version`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_version.html
    pub fn version_str(&self) -> &'static str {
        let version = unsafe {
            let ptr = ffi::SSL_get_version(self.as_ptr());
            CStr::from_ptr(ptr as *const _)
        };

        str::from_utf8(version.to_bytes()).unwrap()
    }

    /// Returns the protocol selected via Application Layer Protocol Negotiation (ALPN).
    ///
    /// The protocol's name is returned is an opaque sequence of bytes. It is up to the client
    /// to interpret it.
    ///
    /// This corresponds to [`SSL_get0_alpn_selected`].
    ///
    /// [`SSL_get0_alpn_selected`]: https://www.openssl.org/docs/manmaster/man3/SSL_get0_next_proto_negotiated.html
    pub fn selected_alpn_protocol(&self) -> Option<&[u8]> {
        unsafe {
            let mut data: *const c_uchar = ptr::null();
            let mut len: c_uint = 0;
            // Get the negotiated protocol from the SSL instance.
            // `data` will point at a `c_uchar` array; `len` will contain the length of this array.
            ffi::SSL_get0_alpn_selected(self.as_ptr(), &mut data, &mut len);

            if data.is_null() {
                None
            } else {
                Some(slice::from_raw_parts(data, len as usize))
            }
        }
    }

    /// Enables the DTLS extension "use_srtp" as defined in RFC5764.
    ///
    /// This corresponds to [`SSL_set_tlsext_use_srtp`].
    ///
    /// [`SSL_set_tlsext_use_srtp`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn set_tlsext_use_srtp(&mut self, protocols: &str) -> Result<(), ErrorStack> {
        unsafe {
            let cstr = CString::new(protocols).unwrap();

            let r = ffi::SSL_set_tlsext_use_srtp(self.as_ptr(), cstr.as_ptr());
            // fun fact, set_tlsext_use_srtp has a reversed return code D:
            if r == 0 {
                Ok(())
            } else {
                Err(ErrorStack::get())
            }
        }
    }

    /// Gets all SRTP profiles that are enabled for handshake via set_tlsext_use_srtp
    ///
    /// DTLS extension "use_srtp" as defined in RFC5764 has to be enabled.
    ///
    /// This corresponds to [`SSL_get_srtp_profiles`].
    ///
    /// [`SSL_get_srtp_profiles`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn srtp_profiles(&self) -> Option<&StackRef<SrtpProtectionProfile>> {
        unsafe {
            let chain = ffi::SSL_get_srtp_profiles(self.as_ptr());

            if chain.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(chain))
            }
        }
    }

    /// Gets the SRTP profile selected by handshake.
    ///
    /// DTLS extension "use_srtp" as defined in RFC5764 has to be enabled.
    ///
    /// This corresponds to [`SSL_get_selected_srtp_profile`].
    ///
    /// [`SSL_get_selected_srtp_profile`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn selected_srtp_profile(&self) -> Option<&SrtpProtectionProfileRef> {
        unsafe {
            let profile = ffi::SSL_get_selected_srtp_profile(self.as_ptr());

            if profile.is_null() {
                None
            } else {
                Some(SrtpProtectionProfileRef::from_ptr(profile as *mut _))
            }
        }
    }

    /// Returns the number of bytes remaining in the currently processed TLS record.
    ///
    /// If this is greater than 0, the next call to `read` will not call down to the underlying
    /// stream.
    ///
    /// This corresponds to [`SSL_pending`].
    ///
    /// [`SSL_pending`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_pending.html
    pub fn pending(&self) -> usize {
        unsafe { ffi::SSL_pending(self.as_ptr()) as usize }
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    ///
    /// It is only useful on the server side.
    ///
    /// This corresponds to [`SSL_get_servername`].
    ///
    /// # Note
    ///
    /// While the SNI specification requires that servernames be valid domain names (and therefore
    /// ASCII), OpenSSL does not enforce this restriction. If the servername provided by the client
    /// is not valid UTF-8, this function will return `None`. The `servername_raw` method returns
    /// the raw bytes and does not have this restriction.
    ///
    /// [`SSL_get_servername`]: https://www.openssl.org/docs/manmaster/man3/SSL_get_servername.html
    // FIXME maybe rethink in 0.11?
    pub fn servername(&self, type_: NameType) -> Option<&str> {
        self.servername_raw(type_)
            .and_then(|b| str::from_utf8(b).ok())
    }

    /// Returns the servername sent by the client via Server Name Indication (SNI).
    ///
    /// It is only useful on the server side.
    ///
    /// This corresponds to [`SSL_get_servername`].
    ///
    /// # Note
    ///
    /// Unlike `servername`, this method does not require the name be valid UTF-8.
    ///
    /// [`SSL_get_servername`]: https://www.openssl.org/docs/manmaster/man3/SSL_get_servername.html
    pub fn servername_raw(&self, type_: NameType) -> Option<&[u8]> {
        unsafe {
            let name = ffi::SSL_get_servername(self.as_ptr(), type_.0);
            if name.is_null() {
                None
            } else {
                Some(CStr::from_ptr(name as *const _).to_bytes())
            }
        }
    }

    /// Changes the context corresponding to the current connection.
    ///
    /// It is most commonly used in the Server Name Indication (SNI) callback.
    ///
    /// This corresponds to `SSL_set_SSL_CTX`.
    pub fn set_ssl_context(&mut self, ctx: &SslContextRef) -> Result<(), ErrorStack> {
        unsafe { cvt_p(ffi::SSL_set_SSL_CTX(self.as_ptr(), ctx.as_ptr())).map(|_| ()) }
    }

    /// Returns the context corresponding to the current connection.
    ///
    /// This corresponds to [`SSL_get_SSL_CTX`].
    ///
    /// [`SSL_get_SSL_CTX`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_get_SSL_CTX.html
    pub fn ssl_context(&self) -> &SslContextRef {
        unsafe {
            let ssl_ctx = ffi::SSL_get_SSL_CTX(self.as_ptr());
            SslContextRef::from_ptr(ssl_ctx)
        }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    ///
    /// This corresponds to [`SSL_get0_param`].
    ///
    /// [`SSL_get0_param`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_get0_param.html
    pub fn param_mut(&mut self) -> &mut X509VerifyParamRef {
        unsafe { X509VerifyParamRef::from_ptr_mut(ffi::SSL_get0_param(self.as_ptr())) }
    }

    /// Returns the certificate verification result.
    ///
    /// This corresponds to [`SSL_get_verify_result`].
    ///
    /// [`SSL_get_verify_result`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_get_verify_result.html
    pub fn verify_result(&self) -> X509VerifyResult {
        unsafe { X509VerifyResult::from_raw(ffi::SSL_get_verify_result(self.as_ptr()) as c_int) }
    }

    /// Returns a shared reference to the SSL session.
    ///
    /// This corresponds to [`SSL_get_session`].
    ///
    /// [`SSL_get_session`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_session.html
    pub fn session(&self) -> Option<&SslSessionRef> {
        unsafe {
            let p = ffi::SSL_get_session(self.as_ptr());
            if p.is_null() {
                None
            } else {
                Some(SslSessionRef::from_ptr(p))
            }
        }
    }

    /// Copies the client_random value sent by the client in the TLS handshake into a buffer.
    ///
    /// Returns the number of bytes copied, or if the buffer is empty, the size of the client_random
    /// value.
    ///
    /// This corresponds to [`SSL_get_client_random`].
    ///
    /// [`SSL_get_client_random`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_client_random.html
    pub fn client_random(&self, buf: &mut [u8]) -> usize {
        unsafe {
            ffi::SSL_get_client_random(self.as_ptr(), buf.as_mut_ptr() as *mut c_uchar, buf.len())
        }
    }

    /// Copies the server_random value sent by the server in the TLS handshake into a buffer.
    ///
    /// Returns the number of bytes copied, or if the buffer is empty, the size of the server_random
    /// value.
    ///
    /// This corresponds to [`SSL_get_server_random`].
    ///
    /// [`SSL_get_server_random`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_client_random.html
    pub fn server_random(&self, buf: &mut [u8]) -> usize {
        unsafe {
            ffi::SSL_get_server_random(self.as_ptr(), buf.as_mut_ptr() as *mut c_uchar, buf.len())
        }
    }

    /// Derives keying material for application use in accordance to RFC 5705.
    ///
    /// This corresponds to [`SSL_export_keying_material`].
    ///
    /// [`SSL_export_keying_material`]: https://www.openssl.org/docs/manmaster/man3/SSL_export_keying_material.html
    pub fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &str,
        context: Option<&[u8]>,
    ) -> Result<(), ErrorStack> {
        unsafe {
            let (context, contextlen, use_context) = match context {
                Some(context) => (context.as_ptr() as *const c_uchar, context.len(), 1),
                None => (ptr::null(), 0, 0),
            };
            cvt(ffi::SSL_export_keying_material(
                self.as_ptr(),
                out.as_mut_ptr() as *mut c_uchar,
                out.len(),
                label.as_ptr() as *const c_char,
                label.len(),
                context,
                contextlen,
                use_context,
            ))
            .map(|_| ())
        }
    }

    /// Sets the session to be used.
    ///
    /// This should be called before the handshake to attempt to reuse a previously established
    /// session. If the server is not willing to reuse the session, a new one will be transparently
    /// negotiated.
    ///
    /// This corresponds to [`SSL_set_session`].
    ///
    /// # Safety
    ///
    /// The caller of this method is responsible for ensuring that the session is associated
    /// with the same `SslContext` as this `Ssl`.
    ///
    /// [`SSL_set_session`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_session.html
    pub unsafe fn set_session(&mut self, session: &SslSessionRef) -> Result<(), ErrorStack> {
        cvt(ffi::SSL_set_session(self.as_ptr(), session.as_ptr())).map(|_| ())
    }

    /// Determines if the session provided to `set_session` was successfully reused.
    ///
    /// This corresponds to [`SSL_session_reused`].
    ///
    /// [`SSL_session_reused`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_session_reused.html
    pub fn session_reused(&self) -> bool {
        unsafe { ffi::SSL_session_reused(self.as_ptr()) != 0 }
    }

    /// Sets the status response a client wishes the server to reply with.
    ///
    /// This corresponds to [`SSL_set_tlsext_status_type`].
    ///
    /// [`SSL_set_tlsext_status_type`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
    pub fn set_status_type(&mut self, type_: StatusType) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_tlsext_status_type(self.as_ptr(), type_.as_raw()) as c_int).map(|_| ())
        }
    }

    /// Returns the server's OCSP response, if present.
    ///
    /// This corresponds to [`SSL_get_tlsext_status_ocsp_resp`].
    ///
    /// [`SSL_get_tlsext_status_ocsp_resp`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
    pub fn ocsp_status(&self) -> Option<&[u8]> {
        unsafe {
            let mut p = ptr::null();
            let len = ffi::SSL_get_tlsext_status_ocsp_resp(self.as_ptr(), &mut p);

            if len == 0 {
                None
            } else {
                Some(slice::from_raw_parts(p as *const u8, len as usize))
            }
        }
    }

    /// Sets the OCSP response to be returned to the client.
    ///
    /// This corresponds to [`SSL_set_tlsext_status_ocsp_resp`].
    ///
    /// [`SSL_set_tlsext_status_ocsp_resp`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
    pub fn set_ocsp_status(&mut self, response: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            assert!(response.len() <= c_int::max_value() as usize);
            let p = cvt_p(ffi::OPENSSL_malloc(response.len() as _))?;
            ptr::copy_nonoverlapping(response.as_ptr(), p as *mut u8, response.len());
            cvt(ffi::SSL_set_tlsext_status_ocsp_resp(
                self.as_ptr(),
                p as *mut c_uchar,
                response.len(),
            ) as c_int)
            .map(|_| ())
        }
    }

    /// Determines if this `Ssl` is configured for server-side or client-side use.
    ///
    /// This corresponds to [`SSL_is_server`].
    ///
    /// [`SSL_is_server`]: https://www.openssl.org/docs/manmaster/man3/SSL_is_server.html
    pub fn is_server(&self) -> bool {
        unsafe { SSL_is_server(self.as_ptr()) != 0 }
    }

    /// Sets the extra data at the specified index.
    ///
    /// This can be used to provide data to callbacks registered with the context. Use the
    /// `Ssl::new_ex_index` method to create an `Index`.
    ///
    /// This corresponds to [`SSL_set_ex_data`].
    ///
    /// [`SSL_set_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_ex_data.html
    pub fn set_ex_data<T>(&mut self, index: Index<Ssl, T>, data: T) {
        unsafe {
            let data = Box::new(data);
            ffi::SSL_set_ex_data(
                self.as_ptr(),
                index.as_raw(),
                Box::into_raw(data) as *mut c_void,
            );
        }
    }

    /// Returns a reference to the extra data at the specified index.
    ///
    /// This corresponds to [`SSL_get_ex_data`].
    ///
    /// [`SSL_get_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_ex_data.html
    pub fn ex_data<T>(&self, index: Index<Ssl, T>) -> Option<&T> {
        unsafe {
            let data = ffi::SSL_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&*(data as *const T))
            }
        }
    }

    /// Returns a mutable reference to the extra data at the specified index.
    ///
    /// This corresponds to [`SSL_get_ex_data`].
    ///
    /// [`SSL_get_ex_data`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_ex_data.html
    pub fn ex_data_mut<T>(&mut self, index: Index<Ssl, T>) -> Option<&mut T> {
        unsafe {
            let data = ffi::SSL_get_ex_data(self.as_ptr(), index.as_raw());
            if data.is_null() {
                None
            } else {
                Some(&mut *(data as *mut T))
            }
        }
    }

    /// Copies the contents of the last Finished message sent to the peer into the provided buffer.
    ///
    /// The total size of the message is returned, so this can be used to determine the size of the
    /// buffer required.
    ///
    /// This corresponds to `SSL_get_finished`.
    pub fn finished(&self, buf: &mut [u8]) -> usize {
        unsafe { ffi::SSL_get_finished(self.as_ptr(), buf.as_mut_ptr() as *mut c_void, buf.len()) }
    }

    /// Copies the contents of the last Finished message received from the peer into the provided
    /// buffer.
    ///
    /// The total size of the message is returned, so this can be used to determine the size of the
    /// buffer required.
    ///
    /// This corresponds to `SSL_get_peer_finished`.
    pub fn peer_finished(&self, buf: &mut [u8]) -> usize {
        unsafe {
            ffi::SSL_get_peer_finished(self.as_ptr(), buf.as_mut_ptr() as *mut c_void, buf.len())
        }
    }

    /// Determines if the initial handshake has been completed.
    ///
    /// This corresponds to [`SSL_is_init_finished`].
    ///
    /// [`SSL_is_init_finished`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_is_init_finished.html
    pub fn is_init_finished(&self) -> bool {
        unsafe { ffi::SSL_is_init_finished(self.as_ptr()) != 0 }
    }

    /// Sets the MTU used for DTLS connections.
    ///
    /// This corresponds to `SSL_set_mtu`.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::SSL_set_mtu(self.as_ptr(), mtu as c_uint) as c_int).map(|_| ()) }
    }
}

/// An SSL stream midway through the handshake process.
#[derive(Debug)]
pub struct MidHandshakeSslStream<S> {
    stream: SslStream<S>,
    error: Error,
}

impl<S> MidHandshakeSslStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Returns a shared reference to the `Ssl` of the stream.
    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    /// Returns the underlying error which interrupted this handshake.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Consumes `self`, returning its error.
    pub fn into_error(self) -> Error {
        self.error
    }

    /// Returns the source data stream.
    pub fn into_source_stream(self) -> S {
        self.stream.into_inner()
    }

    /// Returns both the error and the source data stream, consuming `self`.
    pub fn into_parts(self) -> (Error, S) {
        (self.error, self.stream.into_inner())
    }

    /// Restarts the handshake process.
    ///
    /// This corresponds to [`SSL_do_handshake`].
    ///
    /// [`SSL_do_handshake`]: https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
    pub fn handshake(mut self) -> Result<SslStream<S>, HandshakeError<S>> {
        let ret = unsafe { ffi::SSL_do_handshake(self.stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(self.stream)
        } else {
            self.error = self.stream.make_error(ret);
            match self.error.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    Err(HandshakeError::WouldBlock(self))
                }
                _ => Err(HandshakeError::Failure(self)),
            }
        }
    }
}

/// A TLS session over a stream.
pub struct SslStream<S> {
    ssl: ManuallyDrop<Ssl>,
    method: ManuallyDrop<BioMethod>,
    _p: PhantomData<S>,
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        // ssl holds a reference to method internally so it has to drop first
        unsafe {
            ManuallyDrop::drop(&mut self.ssl);
            ManuallyDrop::drop(&mut self.method);
        }
    }
}

impl<S> fmt::Debug for SslStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SslStream")
            .field("stream", &self.get_ref())
            .field("ssl", &self.ssl())
            .finish()
    }
}

impl<S: Read + Write> SslStream<S> {
    fn new_base(ssl: Ssl, stream: S) -> Self {
        unsafe {
            let (bio, method) = bio::new(stream).unwrap();
            ffi::SSL_set_bio(ssl.as_ptr(), bio, bio);

            SslStream {
                ssl: ManuallyDrop::new(ssl),
                method: ManuallyDrop::new(method),
                _p: PhantomData,
            }
        }
    }

    /// Constructs an `SslStream` from a pointer to the underlying OpenSSL `SSL` struct.
    ///
    /// This is useful if the handshake has already been completed elsewhere.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is valid.
    pub unsafe fn from_raw_parts(ssl: *mut ffi::SSL, stream: S) -> Self {
        let ssl = Ssl::from_ptr(ssl);
        Self::new_base(ssl, stream)
    }

    /// Like `read`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// It is particularly useful with a nonblocking socket, where the error value will identify if
    /// OpenSSL is waiting on read or write readiness.
    ///
    /// This corresponds to [`SSL_read`].
    ///
    /// [`SSL_read`]: https://www.openssl.org/docs/manmaster/man3/SSL_read.html
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // The intepretation of the return code here is a little odd with a
        // zero-length write. OpenSSL will likely correctly report back to us
        // that it read zero bytes, but zero is also the sentinel for "error".
        // To avoid that confusion short-circuit that logic and return quickly
        // if `buf` has a length of zero.
        if buf.is_empty() {
            return Ok(0);
        }

        let ret = self.ssl.read(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Like `write`, but returns an `ssl::Error` rather than an `io::Error`.
    ///
    /// It is particularly useful with a nonblocking socket, where the error value will identify if
    /// OpenSSL is waiting on read or write readiness.
    ///
    /// This corresponds to [`SSL_write`].
    ///
    /// [`SSL_write`]: https://www.openssl.org/docs/manmaster/man3/SSL_write.html
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // See above for why we short-circuit on zero-length buffers
        if buf.is_empty() {
            return Ok(0);
        }

        let ret = self.ssl.write(buf);
        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.make_error(ret))
        }
    }

    /// Shuts down the session.
    ///
    /// The shutdown process consists of two steps. The first step sends a close notify message to
    /// the peer, after which `ShutdownResult::Sent` is returned. The second step awaits the receipt
    /// of a close notify message from the peer, after which `ShutdownResult::Received` is returned.
    ///
    /// While the connection may be closed after the first step, it is recommended to fully shut the
    /// session down. In particular, it must be fully shut down if the connection is to be used for
    /// further communication in the future.
    ///
    /// This corresponds to [`SSL_shutdown`].
    ///
    /// [`SSL_shutdown`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_shutdown.html
    pub fn shutdown(&mut self) -> Result<ShutdownResult, Error> {
        match unsafe { ffi::SSL_shutdown(self.ssl.as_ptr()) } {
            0 => Ok(ShutdownResult::Sent),
            1 => Ok(ShutdownResult::Received),
            n => Err(self.make_error(n)),
        }
    }

    /// Returns the session's shutdown state.
    ///
    /// This corresponds to [`SSL_get_shutdown`].
    ///
    /// [`SSL_get_shutdown`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_set_shutdown.html
    pub fn get_shutdown(&mut self) -> ShutdownState {
        unsafe {
            let bits = ffi::SSL_get_shutdown(self.ssl.as_ptr());
            ShutdownState { bits }
        }
    }

    /// Sets the session's shutdown state.
    ///
    /// This can be used to tell OpenSSL that the session should be cached even if a full two-way
    /// shutdown was not completed.
    ///
    /// This corresponds to [`SSL_set_shutdown`].
    ///
    /// [`SSL_set_shutdown`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_set_shutdown.html
    pub fn set_shutdown(&mut self, state: ShutdownState) {
        unsafe { ffi::SSL_set_shutdown(self.ssl.as_ptr(), state.bits()) }
    }
}

impl<S> SslStream<S> {
    fn make_error(&mut self, ret: c_int) -> Error {
        self.check_panic();

        let code = self.ssl.get_error(ret);

        let cause = match code {
            ErrorCode::SSL => Some(InnerError::Ssl(ErrorStack::get())),
            ErrorCode::SYSCALL => {
                let errs = ErrorStack::get();
                if errs.errors().is_empty() {
                    self.get_bio_error().map(InnerError::Io)
                } else {
                    Some(InnerError::Ssl(errs))
                }
            }
            ErrorCode::ZERO_RETURN => None,
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                self.get_bio_error().map(InnerError::Io)
            }
            _ => None,
        };

        Error { code, cause }
    }

    fn check_panic(&mut self) {
        if let Some(err) = unsafe { bio::take_panic::<S>(self.ssl.get_raw_rbio()) } {
            resume_unwind(err)
        }
    }

    fn get_bio_error(&mut self) -> Option<io::Error> {
        unsafe { bio::take_error::<S>(self.ssl.get_raw_rbio()) }
    }

    /// Converts the SslStream to the underlying data stream.
    pub fn into_inner(self) -> S {
        unsafe { bio::take_stream::<S>(self.ssl.get_raw_rbio()) }
    }

    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_ref(bio)
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        unsafe {
            let bio = self.ssl.get_raw_rbio();
            bio::get_mut(bio)
        }
    }

    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &SslRef {
        &self.ssl
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.ssl_read(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => return Ok(0),
                Err(ref e) if e.code() == ErrorCode::SYSCALL && e.io_error().is_none() => {
                    return Ok(0);
                }
                Err(ref e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
                Err(e) => {
                    return Err(e
                        .into_io_error()
                        .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e)));
                }
            }
        }
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.ssl_write(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.code() == ErrorCode::WANT_READ && e.io_error().is_none() => {}
                Err(e) => {
                    return Err(e
                        .into_io_error()
                        .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e)));
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_mut().flush()
    }
}

/// A partially constructed `SslStream`, useful for unusual handshakes.
pub struct SslStreamBuilder<S> {
    inner: SslStream<S>,
}

impl<S> SslStreamBuilder<S>
where
    S: Read + Write,
{
    /// Begin creating an `SslStream` atop `stream`
    pub fn new(ssl: Ssl, stream: S) -> Self {
        Self {
            inner: SslStream::new_base(ssl, stream),
        }
    }

    /// Configure as an outgoing stream from a client.
    ///
    /// This corresponds to [`SSL_set_connect_state`].
    ///
    /// [`SSL_set_connect_state`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_connect_state.html
    pub fn set_connect_state(&mut self) {
        unsafe { ffi::SSL_set_connect_state(self.inner.ssl.as_ptr()) }
    }

    /// Configure as an incoming stream to a server.
    ///
    /// This corresponds to [`SSL_set_accept_state`].
    ///
    /// [`SSL_set_accept_state`]: https://www.openssl.org/docs/manmaster/man3/SSL_set_accept_state.html
    pub fn set_accept_state(&mut self) {
        unsafe { ffi::SSL_set_accept_state(self.inner.ssl.as_ptr()) }
    }

    /// See `Ssl::connect`
    pub fn connect(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mut stream = self.inner;
        let ret = unsafe { ffi::SSL_connect(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            let error = stream.make_error(ret);
            match error.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    Err(HandshakeError::WouldBlock(MidHandshakeSslStream {
                        stream,
                        error,
                    }))
                }
                _ => Err(HandshakeError::Failure(MidHandshakeSslStream {
                    stream,
                    error,
                })),
            }
        }
    }

    /// See `Ssl::accept`
    pub fn accept(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mut stream = self.inner;
        let ret = unsafe { ffi::SSL_accept(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            let error = stream.make_error(ret);
            match error.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    Err(HandshakeError::WouldBlock(MidHandshakeSslStream {
                        stream,
                        error,
                    }))
                }
                _ => Err(HandshakeError::Failure(MidHandshakeSslStream {
                    stream,
                    error,
                })),
            }
        }
    }

    /// Initiates the handshake.
    ///
    /// This will fail if `set_accept_state` or `set_connect_state` was not called first.
    ///
    /// This corresponds to [`SSL_do_handshake`].
    ///
    /// [`SSL_do_handshake`]: https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
    pub fn handshake(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mut stream = self.inner;
        let ret = unsafe { ffi::SSL_do_handshake(stream.ssl.as_ptr()) };
        if ret > 0 {
            Ok(stream)
        } else {
            let error = stream.make_error(ret);
            match error.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    Err(HandshakeError::WouldBlock(MidHandshakeSslStream {
                        stream,
                        error,
                    }))
                }
                _ => Err(HandshakeError::Failure(MidHandshakeSslStream {
                    stream,
                    error,
                })),
            }
        }
    }
}

impl<S> SslStreamBuilder<S> {
    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        unsafe {
            let bio = self.inner.ssl.get_raw_rbio();
            bio::get_ref(bio)
        }
    }

    /// Returns a mutable reference to the underlying stream.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read from or write to the underlying stream as it
    /// will most likely corrupt the SSL session.
    pub fn get_mut(&mut self) -> &mut S {
        unsafe {
            let bio = self.inner.ssl.get_raw_rbio();
            bio::get_mut(bio)
        }
    }

    /// Returns a shared reference to the `Ssl` object associated with this builder.
    pub fn ssl(&self) -> &SslRef {
        &self.inner.ssl
    }

    /// Set the DTLS MTU size.
    ///
    /// It will be ignored if the value is smaller than the minimum packet size
    /// the DTLS protocol requires.
    ///
    /// # Panics
    /// This function panics if the given mtu size can't be represented in a positive `c_long` range
    #[deprecated(note = "Use SslRef::set_mtu instead", since = "0.10.30")]
    pub fn set_dtls_mtu_size(&mut self, mtu_size: usize) {
        unsafe {
            let bio = self.inner.ssl.get_raw_rbio();
            bio::set_dtls_mtu_size::<S>(bio, mtu_size);
        }
    }
}

/// The result of a shutdown request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownResult {
    /// A close notify message has been sent to the peer.
    Sent,

    /// A close notify response message has been received from the peer.
    Received,
}

bitflags! {
    /// The shutdown state of a session.
    pub struct ShutdownState: c_int {
        /// A close notify message has been sent to the peer.
        const SENT = ffi::SSL_SENT_SHUTDOWN;
        /// A close notify message has been received from the peer.
        const RECEIVED = ffi::SSL_RECEIVED_SHUTDOWN;
    }
}

use ffi::{SSL_CTX_up_ref, SSL_SESSION_get_master_key, SSL_SESSION_up_ref, SSL_is_server};

use ffi::{DTLS_method, TLS_client_method, TLS_method, TLS_server_method};

use std::sync::Once;

unsafe fn get_new_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // hack around https://rt.openssl.org/Ticket/Display.html?id=3710&user=guest&pass=guest
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        ffi::SSL_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None);
    });

    ffi::SSL_CTX_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f)
}

unsafe fn get_new_ssl_idx(f: ffi::CRYPTO_EX_free) -> c_int {
    // hack around https://rt.openssl.org/Ticket/Display.html?id=3710&user=guest&pass=guest
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, None);
    });

    ffi::SSL_get_ex_new_index(0, ptr::null_mut(), ptr::null_mut(), None, f)
}
