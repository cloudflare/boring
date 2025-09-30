use crate::cvt;
use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use std::ffi::c_void;

use foreign_types::ForeignType;

foreign_type_and_impl_send_sync! {
    type CType = ffi::HMAC_CTX;
    fn drop = ffi::HMAC_CTX_free;

    pub struct HmacCtx;
}

impl HmacCtx {
    /// Configures HmacCtx to use `md` as the hash function and `key` as the key.
    ///
    /// https://commondatastorage.googleapis.com/chromium-boringssl-docs/hmac.h.html#HMAC_Init_ex
    ///
    /// # Safety
    ///
    /// The caller must ensure HMAC_CTX has been initalized.
    pub unsafe fn init(&mut self, key: &[u8], md: &MessageDigest) -> Result<(), ErrorStack> {
        ffi::init();

        unsafe {
            cvt(ffi::HMAC_Init_ex(
                self.as_ptr(),
                key.as_ptr() as *const c_void,
                key.len(),
                md.as_ptr(),
                // ENGINE api is deprecated
                core::ptr::null_mut(),
            ))
            .map(|_| ())
        }
    }
}
