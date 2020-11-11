use libc::*;

pub const SHA_CBLOCK: c_uint = 64;

#[repr(C)]
#[derive(Clone)]
pub struct SHA_CTX {
    #[cfg(windows)]
    pub h: [c_uint; 5],

    #[cfg(not(windows))]
    pub h0: c_uint,
    #[cfg(not(windows))]
    pub h1: c_uint,
    #[cfg(not(windows))]
    pub h2: c_uint,
    #[cfg(not(windows))]
    pub h3: c_uint,
    #[cfg(not(windows))]
    pub h4: c_uint,

    pub Nl: c_uint,
    pub Nh: c_uint,
    pub data: [c_uchar; SHA_CBLOCK as usize],
    pub num: c_uint,
}

extern "C" {
    pub fn SHA1_Init(c: *mut SHA_CTX) -> c_int;
    pub fn SHA1_Update(c: *mut SHA_CTX, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA1_Final(md: *mut c_uchar, c: *mut SHA_CTX) -> c_int;
    pub fn SHA1(d: *const c_uchar, n: size_t, md: *mut c_uchar) -> *mut c_uchar;
}

pub const SHA256_CBLOCK: c_int = 64;

#[repr(C)]
#[derive(Clone)]
pub struct SHA256_CTX {
    pub h: [c_uint; 8],
    pub Nl: c_uint,
    pub Nh: c_uint,
    pub data: [c_uchar; SHA256_CBLOCK as usize],
    pub num: c_uint,
    pub md_len: c_uint,
}

extern "C" {
    pub fn SHA224_Init(c: *mut SHA256_CTX) -> c_int;
    pub fn SHA224_Update(c: *mut SHA256_CTX, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA224_Final(md: *mut c_uchar, c: *mut SHA256_CTX) -> c_int;
    pub fn SHA224(d: *const c_uchar, n: size_t, md: *mut c_uchar) -> *mut c_uchar;
    pub fn SHA256_Init(c: *mut SHA256_CTX) -> c_int;
    pub fn SHA256_Update(c: *mut SHA256_CTX, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA256_Final(md: *mut c_uchar, c: *mut SHA256_CTX) -> c_int;
    pub fn SHA256(d: *const c_uchar, n: size_t, md: *mut c_uchar) -> *mut c_uchar;
}

pub const SHA512_CBLOCK: c_int = 128;

#[repr(C)]
#[derive(Clone)]
pub struct SHA512_CTX {
    pub h: [u64; 8],
    pub Nl: u64,
    pub Nh: u64,
    // this is a union but we don't want to require 1.19
    u: [c_uchar; SHA512_CBLOCK as usize],
    pub num: c_uint,
    pub md_len: c_uint,
}

extern "C" {
    pub fn SHA384_Init(c: *mut SHA512_CTX) -> c_int;
    pub fn SHA384_Update(c: *mut SHA512_CTX, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA384_Final(md: *mut c_uchar, c: *mut SHA512_CTX) -> c_int;
    pub fn SHA384(d: *const c_uchar, n: size_t, md: *mut c_uchar) -> *mut c_uchar;
    pub fn SHA512_Init(c: *mut SHA512_CTX) -> c_int;
    pub fn SHA512_Update(c: *mut SHA512_CTX, data: *const c_void, len: size_t) -> c_int;
    pub fn SHA512_Final(md: *mut c_uchar, c: *mut SHA512_CTX) -> c_int;
    pub fn SHA512(d: *const c_uchar, n: size_t, md: *mut c_uchar) -> *mut c_uchar;
}
