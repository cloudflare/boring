use libc::*;
use std::ptr;

use *;

#[cfg(not(any(libressl, ossl110)))]
pub const SSL_MAX_KRB5_PRINCIPAL_LENGTH: c_int = 256;

#[cfg(not(ossl110))]
pub const SSL_MAX_SSL_SESSION_ID_LENGTH: c_int = 32;
#[cfg(not(ossl110))]
pub const SSL_MAX_SID_CTX_LENGTH: c_int = 32;

#[cfg(not(any(libressl, ossl110)))]
pub const SSL_MAX_KEY_ARG_LENGTH: c_int = 8;
#[cfg(not(ossl110))]
pub const SSL_MAX_MASTER_KEY_LENGTH: c_int = 48;

pub const SSL_SENT_SHUTDOWN: c_int = 1;
pub const SSL_RECEIVED_SHUTDOWN: c_int = 2;

pub const SSL_FILETYPE_PEM: c_int = X509_FILETYPE_PEM;
pub const SSL_FILETYPE_ASN1: c_int = X509_FILETYPE_ASN1;

pub enum SSL_METHOD {}
pub enum SSL_CIPHER {}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        pub enum SSL_SESSION {}
    } else {
        #[repr(C)]
        pub struct SSL_SESSION {
            ssl_version: c_int,
            key_arg_length: c_uint,
            key_arg: [c_uchar; SSL_MAX_KEY_ARG_LENGTH as usize],
            pub master_key_length: c_int,
            pub master_key: [c_uchar; 48],
            session_id_length: c_uint,
            session_id: [c_uchar; SSL_MAX_SSL_SESSION_ID_LENGTH as usize],
            sid_ctx_length: c_uint,
            sid_ctx: [c_uchar; SSL_MAX_SID_CTX_LENGTH as usize],
            #[cfg(not(osslconf = "OPENSSL_NO_KRB5"))]
            krb5_client_princ_len: c_uint,
            #[cfg(not(osslconf = "OPENSSL_NO_KRB5"))]
            krb5_client_princ: [c_uchar; SSL_MAX_KRB5_PRINCIPAL_LENGTH as usize],
            #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
            psk_identity_hint: *mut c_char,
            #[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
            psk_identity: *mut c_char,
            not_resumable: c_int,
            sess_cert: *mut c_void,
            peer: *mut X509,
            verify_result: c_long,
            pub references: c_int,
            timeout: c_long,
            time: c_long,
            compress_meth: c_uint,
            cipher: *const c_void,
            cipher_id: c_ulong,
            ciphers: *mut c_void,
            ex_data: ::CRYPTO_EX_DATA,
            prev: *mut c_void,
            next: *mut c_void,
            #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
            tlsext_hostname: *mut c_char,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ecpointformatlist_length: size_t,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ecpointformatlist: *mut c_uchar,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ellipticcurvelist_length: size_t,
            #[cfg(all(
                not(osslconf = "OPENSSL_NO_TLSEXT"),
                not(osslconf = "OPENSSL_NO_EC")
            ))]
            tlsext_ellipticcurvelist: *mut c_uchar,
            #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
            tlsext_tick: *mut c_uchar,
            #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
            tlsext_ticklen: size_t,
            #[cfg(not(osslconf = "OPENSSL_NO_TLSEXT"))]
            tlsext_tick_lifetime_hint: c_long,
            #[cfg(not(osslconf = "OPENSSL_NO_SRP"))]
            srp_username: *mut c_char,
        }
    }
}

stack!(stack_st_SSL_CIPHER);

#[repr(C)]
pub struct SRTP_PROTECTION_PROFILE {
    pub name: *const c_char,
    pub id: c_ulong,
}

stack!(stack_st_SRTP_PROTECTION_PROFILE);

pub const SSL_OP_LEGACY_SERVER_CONNECT: c_uint = 0x00000004;

pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: c_uint = 0x00000800;

pub const SSL_OP_NO_QUERY_MTU: c_uint = 0x00001000;
pub const SSL_OP_NO_TICKET: c_uint = 0x00004000;

pub const SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION: c_uint = 0x00010000;
cfg_if! {
    if #[cfg(ossl101)] {
        pub const SSL_OP_NO_COMPRESSION: c_uint = 0x00020000;
        pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_uint = 0x00040000;
    } else {
        pub const SSL_OP_NO_COMPRESSION: c_uint = 0x0;
        pub const SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION: c_uint = 0x0;
    }
}

pub const SSL_OP_CIPHER_SERVER_PREFERENCE: c_uint = 0x00400000;

pub const SSL_OP_TLS_ROLLBACK_BUG: c_uint = 0x00800000;

cfg_if! {
    if #[cfg(ossl101)] {
        pub const SSL_OP_NO_SSLv3: c_uint = 0x02000000;
    } else {
        pub const SSL_OP_NO_SSLv3: c_uint = 0x0;
    }
}
pub const SSL_OP_NO_TLSv1_1: c_uint = 0x10000000;
pub const SSL_OP_NO_TLSv1_2: c_uint = 0x08000000;

pub const SSL_OP_NO_TLSv1: c_uint = 0x04000000;
#[cfg(ossl102)]
pub const SSL_OP_NO_DTLSv1: c_uint = 0x04000000;
#[cfg(ossl102)]
pub const SSL_OP_NO_DTLSv1_2: c_uint = 0x08000000;

pub const SSL_OP_NO_TLSv1_3: c_uint = 0x20000000;

#[cfg(ossl110h)]
pub const SSL_OP_NO_RENEGOTIATION: c_uint = 0x40000000;

pub const SSL_OP_ALL: c_uint = SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | SSL_OP_LEGACY_SERVER_CONNECT;

cfg_if! {
    if #[cfg(ossl110)] {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_uint = 0x00000000;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_uint = 0x00000000;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_uint = 0x00000000;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_uint = 0x00000000;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_uint = 0x00000000;
        pub const SSL_OP_TLS_D5_BUG: c_uint = 0x00000000;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_uint = 0x00000000;
        pub const SSL_OP_SINGLE_ECDH_USE: c_uint = 0x00000000;
        pub const SSL_OP_SINGLE_DH_USE: c_uint = 0x00000000;
        pub const SSL_OP_NO_SSLv2: c_uint = 0x00000000;
    } else if #[cfg(ossl101)] {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_uint = 0x00000001;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_uint = 0x00000002;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_uint = 0x00000008;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_uint = 0x00000020;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_uint = 0x00000080;
        pub const SSL_OP_TLS_D5_BUG: c_uint = 0x00000100;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_uint = 0x00000200;
        pub const SSL_OP_SINGLE_ECDH_USE: c_uint = 0x00080000;
        pub const SSL_OP_SINGLE_DH_USE: c_uint = 0x00100000;
        pub const SSL_OP_NO_SSLv2: c_uint = 0x01000000;
    } else {
        pub const SSL_OP_MICROSOFT_SESS_ID_BUG: c_uint = 0x0;
        pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: c_uint = 0x0;
        pub const SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: c_uint = 0x0;
        pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: c_uint = 0x0;
        pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: c_uint = 0x0;
        pub const SSL_OP_TLS_D5_BUG: c_uint = 0x0;
        pub const SSL_OP_TLS_BLOCK_PADDING_BUG: c_uint = 0x0;
        pub const SSL_OP_SINGLE_DH_USE: c_uint = 0x00100000;
        pub const SSL_OP_NO_SSLv2: c_uint = 0x0;
    }
}

pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_uint = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_uint = 0x2;
pub const SSL_MODE_AUTO_RETRY: c_uint = 0x4;
pub const SSL_MODE_NO_AUTO_CHAIN: c_uint = 0x8;
pub const SSL_MODE_RELEASE_BUFFERS: c_uint = 0x10;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_CLIENTHELLO_TIME: c_uint = 0x20;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_SERVERHELLO_TIME: c_uint = 0x40;
#[cfg(ossl101)]
pub const SSL_MODE_SEND_FALLBACK_SCSV: c_uint = 0x80;

extern "C" {
    pub fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: c_uint) -> c_uint;
}

extern "C" {
    pub fn SSL_CTX_get_options(ctx: *const SSL_CTX) -> c_uint;
    pub fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: c_uint) -> c_uint;
    pub fn SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: c_uint) -> c_uint;
}

extern "C" {
    pub fn SSL_set_mtu(ssl: *mut SSL, mtu: c_uint) -> c_int;
}

pub const SSL_SESS_CACHE_OFF: c_int = 0x0;
pub const SSL_SESS_CACHE_CLIENT: c_int = 0x1;
pub const SSL_SESS_CACHE_SERVER: c_int = 0x2;
pub const SSL_SESS_CACHE_BOTH: c_int = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_int = 0x80;
pub const SSL_SESS_CACHE_NO_INTERNAL_LOOKUP: c_int = 0x100;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_int = 0x200;
pub const SSL_SESS_CACHE_NO_INTERNAL: c_int =
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE;

extern "C" {
    pub fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SSL_CTX,
        new_session_cb: Option<unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> c_int>,
    );
    pub fn SSL_CTX_sess_set_remove_cb(
        ctx: *mut SSL_CTX,
        remove_session_cb: Option<unsafe extern "C" fn(*mut SSL_CTX, *mut SSL_SESSION)>,
    );
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn SSL_CTX_sess_set_get_cb(
                ctx: *mut ::SSL_CTX,
                get_session_cb: Option<
                    unsafe extern "C" fn(*mut ::SSL, *const c_uchar, c_int, *mut c_int) -> *mut SSL_SESSION,
                >,
            );
        }
    } else {
        extern "C" {
            pub fn SSL_CTX_sess_set_get_cb(
                ctx: *mut ::SSL_CTX,
                get_session_cb: Option<
                    unsafe extern "C" fn(*mut ::SSL, *mut c_uchar, c_int, *mut c_int) -> *mut SSL_SESSION,
                >,
            );
        }
    }
}

extern "C" {
    pub fn SSL_CTX_set_next_protos_advertised_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *const c_uchar,
            outlen: *mut c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    pub fn SSL_CTX_set_next_proto_select_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *mut c_uchar,
            outlen: *mut c_uchar,
            inbuf: *const c_uchar,
            inlen: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    pub fn SSL_get0_next_proto_negotiated(
        s: *const SSL,
        data: *mut *const c_uchar,
        len: *mut c_uint,
    );

    pub fn SSL_select_next_proto(
        out: *mut *mut c_uchar,
        outlen: *mut c_uchar,
        inbuf: *const c_uchar,
        inlen: c_uint,
        client: *const c_uchar,
        client_len: c_uint,
    ) -> c_int;
}

pub const OPENSSL_NPN_UNSUPPORTED: c_int = 0;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;
pub const OPENSSL_NPN_NO_OVERLAP: c_int = 2;

extern "C" {
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_CTX_set_alpn_protos(s: *mut SSL_CTX, data: *const c_uchar, len: c_uint) -> c_int;
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_set_alpn_protos(s: *mut SSL, data: *const c_uchar, len: c_uint) -> c_int;
    // FIXME should take an Option<unsafe extern "C" fn>
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_CTX_set_alpn_select_cb(
        ssl: *mut SSL_CTX,
        cb: extern "C" fn(
            ssl: *mut SSL,
            out: *mut *const c_uchar,
            outlen: *mut c_uchar,
            inbuf: *const c_uchar,
            inlen: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );
    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_get0_alpn_selected(s: *const SSL, data: *mut *const c_uchar, len: *mut c_uint);
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
extern "C" {
    pub fn SSL_CTX_set_psk_client_callback(
        ssl: *mut SSL_CTX,
        psk_client_cb: Option<
            extern "C" fn(
                *mut SSL,
                *const c_char,
                *mut c_char,
                c_uint,
                *mut c_uchar,
                c_uint,
            ) -> c_uint,
        >,
    );
    pub fn SSL_CTX_set_psk_server_callback(
        ssl: *mut SSL_CTX,
        psk_server_cb: Option<
            extern "C" fn(*mut SSL, *const c_char, *mut c_uchar, c_uint) -> c_uint,
        >,
    );
}

extern "C" {
    pub fn SSL_CTX_set_keylog_callback(
        ctx: *mut SSL_CTX,
        cb: Option<unsafe extern "C" fn(ssl: *const SSL, line: *const c_char)>,
    );
    pub fn SSL_get_finished(s: *const SSL, buf: *mut c_void, count: size_t) -> size_t;
    pub fn SSL_get_peer_finished(s: *const SSL, buf: *mut c_void, count: size_t) -> size_t;

    pub fn SSL_CTX_get_verify_mode(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_get_verify_mode(s: *const SSL) -> c_int;
}

extern "C" {
    pub fn SSL_is_init_finished(s: *const SSL) -> c_int;
}

pub const SSL_AD_ILLEGAL_PARAMETER: c_int = SSL3_AD_ILLEGAL_PARAMETER;
pub const SSL_AD_DECODE_ERROR: c_int = TLS1_AD_DECODE_ERROR;
pub const SSL_AD_UNRECOGNIZED_NAME: c_int = TLS1_AD_UNRECOGNIZED_NAME;
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_WANT_ACCEPT: c_int = 8;
pub const SSL_ERROR_WANT_CONNECT: c_int = 7;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_GET_SESSION_REUSED: c_int = 8;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_OPTIONS: c_int = 32;
#[cfg(any(libressl, all(ossl101, not(ossl110))))]
pub const SSL_CTRL_CLEAR_OPTIONS: c_int = 77;
#[cfg(any(libressl, all(ossl102, not(ossl110))))]
pub const SSL_CTRL_SET_ECDH_AUTO: c_int = 94;

extern "C" {
    pub fn SSL_CTX_set_tmp_dh(ctx: *mut SSL_CTX, dh: *const DH) -> c_int;
    pub fn SSL_set_tmp_dh(ssl: *mut SSL, dh: *const DH) -> c_int;
    pub fn SSL_CTX_set_tmp_ecdh(ctx: *mut SSL_CTX, key: *const EC_KEY) -> c_int;
    pub fn SSL_set_tmp_ecdh(ctx: *mut SSL, key: *const EC_KEY) -> c_int;
    pub fn SSL_CTX_add_extra_chain_cert(ctx: *mut SSL_CTX, x509: *mut X509) -> c_int;
    pub fn SSL_CTX_get_extra_chain_certs(
        ctx: *const SSL_CTX,
        chain: *mut *mut stack_st_X509,
    ) -> c_int;
    pub fn SSL_CTX_set0_verify_cert_store(ctx: *mut SSL_CTX, st: *mut X509_STORE) -> c_int;
    pub fn SSL_CTX_set1_sigalgs_list(ctx: *mut SSL_CTX, s: *const c_char) -> c_int;
    pub fn SSL_CTX_set_min_proto_version(ctx: *mut ::SSL_CTX, version: u16) -> c_int;
    pub fn SSL_CTX_set_max_proto_version(ctx: *mut ::SSL_CTX, version: u16) -> c_int;
    pub fn SSL_CTX_get_min_proto_version(ctx: *const ::SSL_CTX) -> u16;
    pub fn SSL_CTX_get_max_proto_version(ctx: *const ::SSL_CTX) -> u16;
    pub fn SSL_set_min_proto_version(s: *mut SSL, version: u16) -> c_int;
    pub fn SSL_set_max_proto_version(s: *mut SSL, version: u16) -> c_int;
    pub fn SSL_get_min_proto_version(s: *const SSL) -> u16;
    pub fn SSL_get_max_proto_version(s: *const SSL) -> u16;
    pub fn SSL_CTX_set_cipher_list(ssl: *mut SSL_CTX, s: *const c_char) -> c_int;
    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    pub fn SSL_CTX_up_ref(x: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_get_cert_store(ctx: *const SSL_CTX) -> *mut X509_STORE;
    pub fn SSL_CTX_set_cert_store(ctx: *mut SSL_CTX, store: *mut X509_STORE);

    pub fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;
    pub fn SSL_CIPHER_get_bits(cipher: *const SSL_CIPHER, alg_bits: *mut c_int) -> c_int;
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn SSL_CIPHER_get_version(cipher: *const SSL_CIPHER) -> *const c_char;
        }
    } else {
        extern "C" {
            pub fn SSL_CIPHER_get_version(cipher: *const SSL_CIPHER) -> *mut c_char;
        }
    }
}
extern "C" {
    pub fn SSL_CIPHER_get_name(cipher: *const SSL_CIPHER) -> *const c_char;
    pub fn SSL_CIPHER_standard_name(cipher: *const SSL_CIPHER) -> *const c_char;

    pub fn SSL_pending(ssl: *const SSL) -> c_int;
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub fn SSL_get_rbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_wbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_set_verify(
        ssl: *mut SSL,
        mode: c_int,
        // FIXME should be unsafe
        verify_callback: Option<extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, key: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, cert: *mut X509) -> c_int;

    pub fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX,
        key_file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    pub fn SSL_CTX_use_certificate_file(
        ctx: *mut SSL_CTX,
        cert_file: *const c_char,
        file_type: c_int,
    ) -> c_int;
    pub fn SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX,
        cert_chain_file: *const c_char,
    ) -> c_int;
    pub fn SSL_load_client_CA_file(file: *const c_char) -> *mut stack_st_X509_NAME;

    #[cfg(not(ossl110))]
    pub fn SSL_load_error_strings();
    pub fn SSL_state_string(ssl: *const SSL) -> *const c_char;
    pub fn SSL_state_string_long(ssl: *const SSL) -> *const c_char;

    pub fn SSL_SESSION_get_time(s: *const SSL_SESSION) -> u64;
    pub fn SSL_SESSION_get_timeout(s: *const SSL_SESSION) -> u32;
    #[cfg(ossl110)]
    pub fn SSL_SESSION_get_protocol_version(s: *const SSL_SESSION) -> u16;

    pub fn SSL_SESSION_get_id(s: *const SSL_SESSION, len: *mut c_uint) -> *const c_uchar;
    #[cfg(any(ossl110, libressl273))]
    pub fn SSL_SESSION_up_ref(ses: *mut SSL_SESSION) -> c_int;
    pub fn SSL_SESSION_free(s: *mut SSL_SESSION);
    pub fn i2d_SSL_SESSION(s: *mut SSL_SESSION, pp: *mut *mut c_uchar) -> c_int;
    pub fn SSL_set_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int;
    pub fn SSL_CTX_add_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int;
    pub fn SSL_CTX_remove_session(ctx: *mut SSL_CTX, session: *mut SSL_SESSION) -> c_int;
    pub fn d2i_SSL_SESSION(
        a: *mut *mut SSL_SESSION,
        pp: *mut *const c_uchar,
        len: c_long,
    ) -> *mut SSL_SESSION;

    pub fn SSL_get_peer_certificate(ssl: *const SSL) -> *mut X509;

    pub fn SSL_get_peer_cert_chain(ssl: *const SSL) -> *mut stack_st_X509;

    pub fn SSL_CTX_set_verify(
        ctx: *mut SSL_CTX,
        mode: c_int,
        verify_callback: Option<extern "C" fn(c_int, *mut X509_STORE_CTX) -> c_int>,
    );
    pub fn SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int);

    pub fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;

    pub fn SSL_CTX_set_session_id_context(
        ssl: *mut SSL_CTX,
        sid_ctx: *const c_uchar,
        sid_ctx_len: size_t,
    ) -> c_int;

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    #[cfg(any(ossl102, libressl261))]
    pub fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;
}

extern "C" {
    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_accept(ssl: *mut SSL) -> c_int;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
}

extern "C" {
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
}

cfg_if! {
    if #[cfg(any(ossl110, libressl291))] {
        extern "C" {
            pub fn TLS_method() -> *const SSL_METHOD;

            pub fn DTLS_method() -> *const SSL_METHOD;

            pub fn TLS_server_method() -> *const SSL_METHOD;

            pub fn TLS_client_method() -> *const SSL_METHOD;
        }
    } else {
        extern "C" {
            #[cfg(not(osslconf = "OPENSSL_NO_SSL3_METHOD"))]
            pub fn SSLv3_method() -> *const SSL_METHOD;

            pub fn SSLv23_method() -> *const SSL_METHOD;

            pub fn SSLv23_client_method() -> *const SSL_METHOD;

            pub fn SSLv23_server_method() -> *const SSL_METHOD;

            pub fn TLSv1_method() -> *const SSL_METHOD;

            pub fn TLSv1_1_method() -> *const SSL_METHOD;

            pub fn TLSv1_2_method() -> *const SSL_METHOD;

            pub fn DTLSv1_method() -> *const SSL_METHOD;

            #[cfg(ossl102)]
            pub fn DTLSv1_2_method() -> *const SSL_METHOD;
        }
    }
}

extern "C" {
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;

    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;

    pub fn SSL_CTX_set_client_CA_list(ctx: *mut SSL_CTX, list: *mut stack_st_X509_NAME);

    #[cfg(not(libressl))]
    pub fn SSL_CTX_add_client_CA(ctx: *mut SSL_CTX, cacert: *mut X509) -> c_int;

    pub fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        CAfile: *const c_char,
        CApath: *const c_char,
    ) -> c_int;
}

extern "C" {
    pub fn SSL_set_connect_state(s: *mut SSL);
    pub fn SSL_set_accept_state(s: *mut SSL);

    #[cfg(not(ossl110))]
    pub fn SSL_library_init() -> c_int;

    pub fn SSL_CIPHER_description(
        cipher: *const SSL_CIPHER,
        buf: *mut c_char,
        size: c_int,
    ) -> *const c_char;

    pub fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
}
cfg_if! {
    if #[cfg(any(ossl102, libressl280))] {
        extern "C" {
            pub fn SSL_get_privatekey(ssl: *const SSL) -> *mut EVP_PKEY;
        }
    } else {
        extern "C" {
            pub fn SSL_get_privatekey(ssl: *mut SSL) -> *mut EVP_PKEY;
        }
    }
}

extern "C" {
    #[cfg(ossl102)]
    pub fn SSL_CTX_get0_certificate(ctx: *const SSL_CTX) -> *mut X509;
    #[cfg(ossl102)]
    pub fn SSL_CTX_get0_privatekey(ctx: *const SSL_CTX) -> *mut EVP_PKEY;

    pub fn SSL_set_shutdown(ss: *mut SSL, mode: c_int);
    pub fn SSL_get_shutdown(ssl: *const SSL) -> c_int;
    pub fn SSL_version(ssl: *const SSL) -> c_int;
    pub fn SSL_get_session(s: *const SSL) -> *mut SSL_SESSION;
    pub fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;
    pub fn SSL_set_SSL_CTX(ssl: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX;

    pub fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
    #[cfg(ossl110)]
    pub fn SSL_get_client_random(ssl: *const SSL, out: *mut c_uchar, len: size_t) -> size_t;
    #[cfg(ossl110)]
    pub fn SSL_get_server_random(ssl: *const SSL, out: *mut c_uchar, len: size_t) -> size_t;
    #[cfg(any(ossl110, libressl273))]
    pub fn SSL_SESSION_get_master_key(
        session: *const SSL_SESSION,
        out: *mut c_uchar,
        outlen: size_t,
    ) -> size_t;
}

extern "C" {
    pub fn SSL_get_ex_new_index(
        argl: c_long,
        argp: *mut c_void,
        new_func: *mut c_int,
        dup_func: Option<CRYPTO_EX_dup>,
        free_func: Option<CRYPTO_EX_free>,
    ) -> c_int;
}

extern "C" {
    pub fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;
}

extern "C" {
    pub fn SSL_CTX_get_ex_new_index(
        argl: c_long,
        argp: *mut c_void,
        new_func: *mut c_int,
        dup_func: Option<::CRYPTO_EX_dup>,
        free_func: Option<::CRYPTO_EX_free>,
    ) -> c_int;
}

extern "C" {
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void;

    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
}

extern "C" {
    pub fn SSL_CTX_sess_set_cache_size(ctx: *mut SSL_CTX, t: c_ulong) -> c_ulong;
    pub fn SSL_CTX_sess_get_cache_size(ctx: *const SSL_CTX) -> c_ulong;
    pub fn SSL_CTX_set_session_cache_mode(ctx: *mut SSL_CTX, m: c_int) -> c_int;
    pub fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_int) -> c_int;
}

extern "C" {
    // FIXME should take an option
    #[cfg(not(ossl110))]
    pub fn SSL_CTX_set_tmp_ecdh_callback(
        ctx: *mut ::SSL_CTX,
        ecdh: unsafe extern "C" fn(
            ssl: *mut ::SSL,
            is_export: c_int,
            keylength: c_int,
        ) -> *mut ::EC_KEY,
    );
    // FIXME should take an option
    #[cfg(not(ossl110))]
    pub fn SSL_set_tmp_ecdh_callback(
        ssl: *mut SSL,
        ecdh: unsafe extern "C" fn(
            ssl: *mut SSL,
            is_export: c_int,
            keylength: c_int,
        ) -> *mut EC_KEY,
    );
}

cfg_if! {
    if #[cfg(osslconf = "OPENSSL_NO_COMP")] {
    } else {
        extern "C" {
            pub fn SSL_get_current_compression(ssl: *mut SSL) -> *const COMP_METHOD;
        }
    }
}
cfg_if! {
    if #[cfg(not(osslconf = "OPENSSL_NO_COMP"))] {
        extern "C" {
            pub fn SSL_COMP_get_name(comp: *const COMP_METHOD) -> *const c_char;
        }
    }
}

extern "C" {
    #[cfg(ossl110)]
    pub fn SSL_CIPHER_get_cipher_nid(c: *const SSL_CIPHER) -> c_int;
    #[cfg(ossl110)]
    pub fn SSL_CIPHER_get_digest_nid(c: *const SSL_CIPHER) -> c_int;
}

extern "C" {
    pub fn SSL_session_reused(ssl: *const SSL) -> c_int;
}

extern "C" {
    pub fn SSL_is_server(s: *const SSL) -> c_int;
}

#[cfg(ossl110)]
pub const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x00200000;

extern "C" {
    #[cfg(ossl110)]
    pub fn OPENSSL_init_ssl(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int;
}
