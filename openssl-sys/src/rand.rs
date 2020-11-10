use libc::*;

extern "C" {
    pub fn RAND_bytes(buf: *mut u8, num: size_t) -> c_int;

    #[cfg(ossl111)]
    pub fn RAND_keep_random_devices_open(keep: c_int);

    pub fn RAND_status() -> c_int;
}
