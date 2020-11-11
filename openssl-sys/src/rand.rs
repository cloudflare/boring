use libc::*;

extern "C" {
    pub fn RAND_bytes(buf: *mut u8, num: size_t) -> c_int;
    pub fn RAND_status() -> c_int;
}
