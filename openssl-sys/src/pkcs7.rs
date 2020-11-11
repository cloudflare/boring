use libc::*;

use *;

pub enum PKCS7_SIGNED {}
pub enum PKCS7_ENVELOPE {}
pub enum PKCS7_SIGN_ENVELOPE {}
pub enum PKCS7_DIGEST {}
pub enum PKCS7_ENCRYPT {}
pub enum PKCS7 {}

pub const PKCS7_TEXT: c_int = 0x1;
pub const PKCS7_NOCERTS: c_int = 0x2;
pub const PKCS7_NOSIGS: c_int = 0x4;
pub const PKCS7_NOCHAIN: c_int = 0x8;
pub const PKCS7_NOINTERN: c_int = 0x10;
pub const PKCS7_NOVERIFY: c_int = 0x20;
pub const PKCS7_DETACHED: c_int = 0x40;
pub const PKCS7_BINARY: c_int = 0x80;
pub const PKCS7_NOATTR: c_int = 0x100;
pub const PKCS7_NOSMIMECAP: c_int = 0x200;
pub const PKCS7_STREAM: c_int = 0x1000;

extern "C" {
    pub fn d2i_PKCS7(a: *mut *mut PKCS7, pp: *mut *const c_uchar, length: size_t) -> *mut PKCS7;

    pub fn i2d_PKCS7(a: *const PKCS7, buf: *mut *mut u8) -> c_int;

    pub fn PKCS7_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_int,
    ) -> *mut PKCS7;

    pub fn PKCS7_free(pkcs7: *mut PKCS7);
}
