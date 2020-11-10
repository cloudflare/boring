use libc::*;

#[repr(C)]
pub struct _STACK {
    pub num: size_t,
    pub data: *mut *mut c_void,
    pub sorted: c_int,
    pub num_alloc: size_t,
    pub comp: Option<unsafe extern "C" fn(*mut *const c_void, *mut *const c_void) -> c_int>,
}

extern "C" {
    pub fn sk_num(st: *const _STACK) -> size_t;
    pub fn sk_value(st: *const _STACK, n: size_t) -> *mut c_void;

    pub fn sk_new_null() -> *mut _STACK;
    pub fn sk_free(st: *mut _STACK);
    pub fn sk_pop_free(st: *mut _STACK, free: Option<unsafe extern "C" fn(*mut c_void)>);
    pub fn sk_push(st: *mut _STACK, data: *mut c_void) -> size_t;
    pub fn sk_pop(st: *mut _STACK) -> *mut c_void;
}
