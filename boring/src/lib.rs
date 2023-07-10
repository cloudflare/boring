//! Bindings to BoringSSL
//!
//! This crate provides a safe interface to the BoringSSL cryptography library.
//!
//! # Versioning
//!
//! ## Crate versioning
//!
//! The crate and all the related crates (FFI bindings, etc.) are released simultaneously and all
//! bumped to the same version disregard whether particular crate has any API changes or not.
//! However, semantic versioning guarantees still hold, as all the crate versions will be updated
//! based on the crate with most significant changes.
//!
//! ## BoringSSL version
//!
//! By default, the crate aims to statically link with the latest BoringSSL master branch.
//! *Note*: any BoringSSL revision bumps will be released as a major version update of all crates.
//!
//! # Compilation and linking options
//!
//! ## Support for pre-built binaries
//!
//! While this crate can build BoringSSL on its own, you may want to provide pre-built binaries instead.
//! To do so, specify the environment variable `BORING_BSSL_PATH` with the path to the binaries.
//!
//! You can also provide specific headers by setting `BORING_BSSL_INCLUDE_PATH`.
//!
//! _Notes_: The crate will look for headers in the `$BORING_BSSL_INCLUDE_PATH/openssl/` folder, make sure to place your headers there.
//!
//! _Warning_: When providing a different version of BoringSSL make sure to use a compatible one, the crate relies on the presence of certain functions.
//!
//! ## Building with a FIPS-validated module
//!
//! Only BoringCrypto module version `853ca1ea1168dff08011e5d42d94609cc0ca2e27`, as certified with
//! [FIPS 140-2 certificate 4407](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407)
//! is supported by this crate. Support is enabled by this crate's `fips` feature.
//!
//! `boring-sys` comes with a test that FIPS is enabled/disabled depending on the feature flag. You can run it as follows:
//!
//! ```bash
//! $ cargo test --features fips fips::is_enabled
//! ```
//!
//! # Optional patches
//!
//! ## Raw Public Key
//!
//! The crate can be compiled with [RawPublicKey](https://datatracker.ietf.org/doc/html/rfc7250)
//! support by turning on `rpk` compilation feature.
//!
//! ## Post-quantum cryptography
//!
//! The crate can be compiled with [post-quantum cryptography](https://blog.cloudflare.com/post-quantum-for-all/)
//! support by turning on `post-quantum` compilation feature.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

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
