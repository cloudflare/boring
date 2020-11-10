use libc::*;

pub const ERR_FLAG_STRING: c_int = 0x01;

pub const ERR_LIB_PEM: c_int = 9;

const_fn! {
    pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
        ((l as c_ulong & 0x0FF) << 24) |
        ((f as c_ulong & 0xFFF) << 12) |
        (r as c_ulong & 0xFFF)
    }

    pub const fn ERR_GET_LIB(l: c_uint) -> c_int {
        ((l >> 24) & 0x0FF) as c_int
    }

    pub const fn ERR_GET_FUNC(l: c_uint) -> c_int {
        ((l >> 12) & 0xFFF) as c_int
    }

    pub const fn ERR_GET_REASON(l: c_uint) -> c_int {
        (l & 0xFFF) as c_int
    }
}

extern "C" {
    pub fn ERR_put_error(lib: c_int, func: c_int, reason: c_int, file: *const c_char, line: c_uint);
    pub fn ERR_add_error_data(count: c_uint, ...);

    pub fn ERR_get_error() -> c_uint;
    pub fn ERR_get_error_line_data(
        file: *mut *const c_char,
        line: *mut c_int,
        data: *mut *const c_char,
        flags: *mut c_int,
    ) -> c_uint;
    pub fn ERR_peek_last_error() -> c_uint;
    pub fn ERR_clear_error();
    pub fn ERR_lib_error_string(err: c_uint) -> *const c_char;
    pub fn ERR_func_error_string(err: c_uint) -> *const c_char;
    pub fn ERR_reason_error_string(err: c_uint) -> *const c_char;
    #[cfg(not(ossl110))]
    pub fn ERR_load_crypto_strings();

    pub fn ERR_get_next_error_library() -> c_int;
}
