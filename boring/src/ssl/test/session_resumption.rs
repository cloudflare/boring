use super::server::Server;
use crate::ssl::test::MessageDigest;
use crate::ssl::SslRef;
use crate::ssl::SslSession;
use crate::ssl::SslSessionCacheMode;
use crate::ssl::TicketKeyCallbackResult;
use crate::symm::Cipher;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

static SUCCESS_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static SUCCESS_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);

#[test]
fn resume_session() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(&session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
}

#[test]
fn custom_callback_success() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_ticket_key_callback(test_success_tickey_key_callback);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(&session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

#[test]
fn custom_callback_unrecognized_decryption_ticket() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_ticket_key_callback(test_noop_tickey_key_callback);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(&session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    // Second connection was NOT resumed due to TicketKeyCallbackResult::Noop on decryption
    assert!(!ssl_stream_2.ssl().session_reused());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

// Successfully return a session ticket in encryption mode but return a
// TicketKeyCallbackResult::Noop in decryption mode.
fn test_noop_tickey_key_callback(
    _ssl: &SslRef,
    _key_name: &mut [u8; 16],
    _iv: *mut u8,
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    hmac_ctx: *mut ffi::HMAC_CTX,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_CBC_IV: [u8; 16] = [1; 16];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        NOOP_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);
        // Set the encryption context.
        let ret = unsafe {
            ffi::EVP_EncryptInit_ex(
                evp_ctx,
                cipher.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
                TEST_AES_128_CBC_KEY.as_ptr(),
                TEST_CBC_IV.as_ptr(),
            )
        };
        assert!(ret == 1);

        // Set the hmac context.
        let ret = unsafe {
            ffi::HMAC_Init_ex(
                hmac_ctx,
                TEST_HMAC_KEY.as_ptr() as *const c_void,
                TEST_HMAC_KEY.len(),
                digest.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
            )
        };
        assert!(ret == 1);

        TicketKeyCallbackResult::Success
    } else {
        NOOP_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);
        TicketKeyCallbackResult::Noop
    }
}

// Custom callback to encrypt and decrypt session tickets
fn test_success_tickey_key_callback(
    _ssl: &SslRef,
    _key_name: &mut [u8; 16],
    _iv: *mut u8,
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    hmac_ctx: *mut ffi::HMAC_CTX,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_CBC_IV: [u8; 16] = [1; 16];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        SUCCESS_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);
        // Set the encryption context.
        let ret = unsafe {
            ffi::EVP_EncryptInit_ex(
                evp_ctx,
                cipher.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
                TEST_AES_128_CBC_KEY.as_ptr(),
                TEST_CBC_IV.as_ptr(),
            )
        };
        assert!(ret == 1);

        // Set the hmac context.
        let ret = unsafe {
            ffi::HMAC_Init_ex(
                hmac_ctx,
                TEST_HMAC_KEY.as_ptr() as *const c_void,
                TEST_HMAC_KEY.len(),
                digest.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
            )
        };
        assert!(ret == 1);
    } else {
        SUCCESS_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);
        let ret = unsafe {
            ffi::EVP_DecryptInit_ex(
                evp_ctx,
                cipher.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
                TEST_AES_128_CBC_KEY.as_ptr(),
                TEST_CBC_IV.as_ptr(),
            )
        };
        assert!(ret == 1);

        // Set the hmac context.
        let ret = unsafe {
            ffi::HMAC_Init_ex(
                hmac_ctx,
                TEST_HMAC_KEY.as_ptr() as *const c_void,
                TEST_HMAC_KEY.len(),
                digest.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
            )
        };
        assert!(ret == 1);
    }

    TicketKeyCallbackResult::Success
}
