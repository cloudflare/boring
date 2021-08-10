//! Bindings to BoringSSL
//!
//! This crate provides a safe interface to the BoringSSL cryptography library.

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate foreign_types;
#[macro_use]
extern crate lazy_static;
extern crate boring_sys as ffi;
extern crate libc;

#[cfg(test)]
extern crate hex;

#[doc(inline)]
pub use crate::ffi::init;

use libc::{c_int, size_t};

use crate::error::ErrorStack;

#[macro_use]
mod macros;

mod bio;
#[macro_use]
mod util;
pub mod aes;
pub mod asn1;
pub mod base64;
pub mod bn;
pub mod conf;
pub mod derive;
pub mod dh;
pub mod dsa;
pub mod ec;
pub mod ecdsa;
pub mod error;
pub mod ex_data;
pub mod fips;
pub mod hash;
pub mod memcmp;
pub mod nid;
pub mod pkcs12;
pub mod pkcs5;
pub mod pkey;
pub mod rand;
pub mod rsa;
pub mod sha;
pub mod sign;
pub mod srtp;
pub mod ssl;
pub mod stack;
pub mod string;
pub mod symm;
pub mod version;
pub mod x509;

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_0(r: size_t) -> Result<size_t, ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_0i(r: c_int) -> Result<c_int, ErrorStack> {
    if r == 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
