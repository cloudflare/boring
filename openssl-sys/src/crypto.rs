use libc::*;

use *;

stack!(stack_st_void);

extern "C" {
    pub fn OpenSSL_version_num() -> c_ulong;
    pub fn OpenSSL_version(key: c_int) -> *const c_char;
}
pub const OPENSSL_VERSION: c_int = 0;
pub const OPENSSL_CFLAGS: c_int = 1;
pub const OPENSSL_BUILT_ON: c_int = 2;
pub const OPENSSL_PLATFORM: c_int = 3;
pub const OPENSSL_DIR: c_int = 4;

// FIXME should be options
pub type CRYPTO_EX_new = unsafe extern "C" fn(
    parent: *mut c_void,
    ptr: *mut c_void,
    ad: *const CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: *const c_void,
) -> c_int;
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    to: *mut CRYPTO_EX_DATA,
    from: *mut CRYPTO_EX_DATA,
    from_d: *mut c_void,
    idx: c_int,
    argl: c_long,
    argp: *mut c_void,
) -> c_int;
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    parent: *mut c_void,
    ptr: *mut c_void,
    ad: *mut CRYPTO_EX_DATA,
    idx: c_int,
    argl: c_long,
    argp: *mut c_void,
);

pub const CRYPTO_LOCK: c_int = 1;

extern "C" {
    pub fn OPENSSL_malloc(num: size_t) -> *mut c_void;
    pub fn OPENSSL_free(buf: *mut c_void);
}

extern "C" {
    pub fn FIPS_mode() -> c_int;
    pub fn FIPS_mode_set(onoff: c_int) -> c_int;

    pub fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: size_t) -> c_int;
}
