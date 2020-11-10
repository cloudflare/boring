use *;

extern "C" {
    pub fn DH_new() -> *mut DH;
    pub fn DH_free(dh: *mut DH);

    pub fn d2i_DHparams(k: *mut *mut DH, pp: *mut *const c_uchar, length: c_long) -> *mut DH;
    pub fn i2d_DHparams(dh: *const DH, pp: *mut *mut c_uchar) -> c_int;

    #[cfg(any(ossl110, libressl273))]
    pub fn DH_set0_pqg(dh: *mut DH, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> c_int;
}
