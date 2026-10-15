//! Regression test for clearing the certificate callback.
//!
//! `SSL_set_cert_cb(ssl, NULL, arg)` must leave the connection without a
//! certificate callback. The BoringSSL revision shipped in 5.3.0 stores the
//! null pointer as an "old" callback instead of resetting the variant to
//! `monostate`, so `do_cert_callback` later invokes a null function pointer
//! and crashes the process (cloudflare/boring#537). The patch applied from
//! `boring-sys/patches/cert-cb-clear.patch` restores the previous "NULL
//! clears" behavior; without it this test aborts instead of completing the
//! handshake.

use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use super::server::Server;
use crate::ffi;
use crate::foreign_types::ForeignTypeRef;

unsafe extern "C" fn block_cert_cb(_ssl: *mut ffi::SSL, _arg: *mut c_void) -> c_int {
    -1
}

#[test]
fn clearing_the_certificate_callback_serves_the_handshake() {
    let mut server = Server::builder();
    server.ssl_cb(|ssl| {
        // Mirror the resumable-accept dance: arm the blocking callback, then
        // clear it before the handshake starts, the way a paused handshake is
        // resumed with the certificate installed.
        unsafe {
            ffi::SSL_set_cert_cb(ssl.as_ptr(), Some(block_cert_cb), ptr::null_mut());
            ffi::SSL_set_cert_cb(ssl.as_ptr(), None, ptr::null_mut());
        }
    });
    let server = server.build();

    server.client_with_root_ca().connect();
}
