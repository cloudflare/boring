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
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use std::convert::TryInto;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint, c_ulong};

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

pub fn init() {
    use std::ptr;
    use std::sync::Once;

    // explicitly initialize to work around https://github.com/openssl/openssl/issues/3505
    static INIT: Once = Once::new();

    let init_options = OPENSSL_INIT_LOAD_SSL_STRINGS;

    INIT.call_once(|| {
        assert_eq!(
            unsafe { OPENSSL_init_ssl(init_options.try_into().unwrap(), ptr::null_mut()) },
            1
        )
    });
}
