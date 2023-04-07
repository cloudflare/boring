#![allow(
    clippy::missing_safety_doc,
    clippy::redundant_static_lifetimes,
    clippy::too_many_arguments,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]
#![cfg_attr(not(test), no_std)]

use core::convert::TryInto;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

#[allow(clippy::useless_transmute, clippy::derive_partial_eq_without_eq)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use generated::*;

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = u64;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = u32;

#[cfg(const_fn)]
macro_rules! const_fn {
    ($(pub const fn $name:ident($($arg:ident: $t:ty),*) -> $ret:ty $b:block)*) => {
        $(
            pub const fn $name($($arg: $t),*) -> $ret $b
        )*
    }
}

#[cfg(not(const_fn))]
macro_rules! const_fn {
    ($(pub const fn $name:ident($($arg:ident: $t:ty),*) -> $ret:ty $b:block)*) => {
        $(
            pub fn $name($($arg: $t),*) -> $ret $b
        )*
    }
}

const_fn! {
    pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
        ((l as c_ulong & 0x0FF) << 24) |
        ((f as c_ulong & 0xFFF) << 12) |
        (r as c_ulong & 0xFFF)
    }

    pub const fn ERR_GET_LIB(l: c_uint) -> c_int {
        ((l >> 24) & 0x0FF) as c_int
    }

    pub const fn ERR_GET_FUNC(l: c_uint) -> c_int {
        ((l >> 12) & 0xFFF) as c_int
    }

    pub const fn ERR_GET_REASON(l: c_uint) -> c_int {
        (l & 0xFFF) as c_int
    }
}

//// Initialize BoringSSL.
///
/// This function must be called before using any library
/// routines.
///
// See https://github.com/openssl/openssl/issues/3505
pub fn init() {
    use core::ptr;
    use core::sync::atomic::{AtomicBool, Ordering};

    // lock is a spinlock guarding access to OPENSSL_init_ssl.
    static lock: AtomicBool = AtomicBool::new(false);

    // done is true if we have invoked OPENSSL_init_ssl.
    static done: AtomicBool = AtomicBool::new(false);

    if done.load(Ordering::SeqCst) {
        // Fast path: we've already invoked OPENSSL_init_ssl.
        return;
    }

    loop {
        let res = lock.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed);
        match res {
            Ok(_) => break,
            Err(_) => (),
        }
    }

    if done.load(Ordering::SeqCst) {
        // Check again: perhaps somebody invoked OPENSSL_init_ssl
        // while we were spinning.
        return;
    }

    let opts = OPENSSL_INIT_LOAD_SSL_STRINGS;
    assert_eq!(
        unsafe { OPENSSL_init_ssl(opts.try_into().unwrap(), ptr::null_mut()) },
        1
    );

    // Mark that we've finished prior to releasing the spinlock.
    // Otherwise, somebody else could see done=false before we're
    // able to mark our progress.
    done.store(true, Ordering::SeqCst);
    lock.store(false, Ordering::SeqCst)
}
