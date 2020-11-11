use libc::*;

pub const AES_ENCRYPT: c_int = 1;
pub const AES_DECRYPT: c_int = 0;

pub const AES_MAXNR: c_int = 14;
pub const AES_BLOCK_SIZE: c_int = 16;

#[repr(C)]
pub struct AES_KEY {
    // There is some business with AES_LONG which is there to ensure the values here are 32 bits
    rd_key: [u32; 4 * (AES_MAXNR as usize + 1)],
    rounds: c_uint,
}

extern "C" {
    pub fn AES_set_encrypt_key(userKey: *const c_uchar, bits: c_uint, key: *mut AES_KEY) -> c_int;
    pub fn AES_set_decrypt_key(userKey: *const c_uchar, bits: c_uint, key: *mut AES_KEY) -> c_int;

    pub fn AES_wrap_key(
        key: *const AES_KEY,
        iv: *const c_uchar,
        out: *mut c_uchar,
        in_: *const c_uchar,
        inlen: size_t,
    ) -> c_int;

    pub fn AES_unwrap_key(
        key: *const AES_KEY,
        iv: *const c_uchar,
        out: *mut c_uchar,
        in_: *const c_uchar,
        inlen: size_t,
    ) -> c_int;
}
