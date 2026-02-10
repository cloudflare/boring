#![allow(unused, deprecated)]

use crate::{ERR_put_error, CBB, CBS, ERR_R_FATAL};
use std::os::raw::c_int;
use std::process::abort;

#[derive(Copy, Clone, Default)]
pub struct UnimplementedPlaceholder {
    pub bytes: [u8; 0],
}

#[derive(Copy, Clone, Default)]
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub struct MLKEM768_private_key {
    pub opaque: UnimplementedPlaceholder,
}

#[derive(Copy, Clone, Default)]
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub struct MLKEM768_public_key;
#[derive(Copy, Clone, Default)]
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub struct MLKEM1024_private_key {
    pub opaque: UnimplementedPlaceholder,
}
#[derive(Copy, Clone, Default)]
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub struct MLKEM1024_public_key;

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM_SEED_BYTES: u32 = 0;
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM_SHARED_SECRET_BYTES: u32 = 0;
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM768_PUBLIC_KEY_BYTES: u32 = 0;
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM1024_PUBLIC_KEY_BYTES: u32 = 0;
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM768_CIPHERTEXT_BYTES: u32 = 0;
#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub const MLKEM1024_CIPHERTEXT_BYTES: u32 = 0;

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM1024_generate_key(
    _out_encoded_public_key: *mut u8,
    _optional_out_seed: *mut u8,
    _out_private_key: *mut MLKEM1024_private_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM1024_private_key_from_seed(
    _out_private_key: *mut MLKEM1024_private_key,
    _seed: *const u8,
    _seed_len: usize,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM1024_public_from_private(
    _out_public_key: *mut MLKEM1024_public_key,
    _private_key: *const MLKEM1024_private_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM1024_encap(
    _out_ciphertext: *mut u8,
    _out_shared_secret: *mut u8,
    _public_key: *const MLKEM1024_public_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM1024_decap(
    _out_shared_secret: *mut u8,
    _ciphertext: *const u8,
    _ciphertext_len: usize,
    _private_key: *const MLKEM1024_private_key,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM768_generate_key(
    _out_encoded_public_key: *mut u8,
    _optional_out_seed: *mut u8,
    _out_private_key: *mut MLKEM768_private_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM768_private_key_from_seed(
    _out_private_key: *mut MLKEM768_private_key,
    _seed: *const u8,
    _seed_len: usize,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM768_public_from_private(
    _out_public_key: *mut MLKEM768_public_key,
    _private_key: *const MLKEM768_private_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C-unwind" fn MLKEM768_encap(
    _out_ciphertext: *mut u8,
    _out_shared_secret: *mut u8,
    _public_key: *const MLKEM768_public_key,
) {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM768_decap(
    _out_shared_secret: *mut u8,
    _ciphertext: *const u8,
    _ciphertext_len: usize,
    _private_key: *const MLKEM768_private_key,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM768_marshal_public_key(
    out: *mut CBB,
    public_key: *const MLKEM768_public_key,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM768_parse_public_key(
    out_public_key: *mut MLKEM768_public_key,
    in_: *mut CBS,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM1024_marshal_public_key(
    out: *mut CBB,
    public_key: *const MLKEM1024_public_key,
) -> c_int {
    abort();
}

#[deprecated(note = "mlkem.h was missing; this API won't work")]
pub unsafe extern "C" fn MLKEM1024_parse_public_key(
    out_public_key: *mut MLKEM1024_public_key,
    in_: *mut CBS,
) -> c_int {
    abort();
}
