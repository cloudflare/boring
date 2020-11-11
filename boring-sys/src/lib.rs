#![allow(
    clippy::missing_safety_doc,
    clippy::unreadable_literal,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    overflowing_literals,
    unused_imports
)]

extern crate libc;

use libc::*;

pub use aes::*;
pub use asn1::*;
pub use bio::*;
pub use bn::*;
pub use conf::*;
pub use crypto::*;
pub use dh::*;
pub use dsa::*;
pub use ec::*;
pub use err::*;
pub use evp::*;
pub use hmac::*;
pub use obj_mac::*;
pub use object::*;
pub use ossl_typ::*;
pub use pem::*;
pub use pkcs12::*;
pub use pkcs7::*;
pub use rand::*;
pub use rsa::*;
pub use safestack::*;
pub use sha::*;
pub use srtp::*;
pub use ssl::*;
pub use ssl3::*;
pub use stack::*;
pub use tls1::*;
pub use x509::*;
pub use x509_vfy::*;
pub use x509v3::*;

#[macro_use]
mod macros;

mod aes;
mod asn1;
mod bio;
mod bn;
mod conf;
mod crypto;
mod dh;
mod dsa;
mod ec;
mod err;
mod evp;
mod hmac;
mod obj_mac;
mod object;
mod ossl_typ;
mod pem;
mod pkcs12;
mod pkcs7;
mod rand;
mod rsa;
mod safestack;
mod sha;
mod srtp;
mod ssl;
mod ssl3;
mod stack;
mod tls1;
mod x509;
mod x509_vfy;
mod x509v3;

// FIXME remove
pub type PasswordCallback = unsafe extern "C" fn(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    user_data: *mut c_void,
) -> c_int;

pub fn init() {
    use std::ptr;
    use std::sync::Once;

    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();

    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS;

    INIT.call_once(|| unsafe {
        OPENSSL_init_ssl(init_options, ptr::null_mut());
    })
}
