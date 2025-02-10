use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;

use crate::error::ErrorStack;
use crate::hpke::HpkeKey;
use crate::{cvt_0i, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_ECH_KEYS;
    fn drop = ffi::SSL_ECH_KEYS_free;

    pub struct SslEchKeys;
}

impl SslEchKeys {
    pub fn new() -> Result<SslEchKeys, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::SSL_ECH_KEYS_new()).map(|p| SslEchKeys::from_ptr(p))
        }
    }
}

impl SslEchKeysRef {
    pub fn add_key(
        &mut self,
        is_retry_config: bool,
        ech_config: &[u8],
        key: HpkeKey,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_ECH_KEYS_add(
                self.as_ptr(),
                is_retry_config as c_int,
                ech_config.as_ptr(),
                ech_config.len(),
                key.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}
