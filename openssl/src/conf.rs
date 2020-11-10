//! Interface for processing OpenSSL configuration files.
use ffi;
use libc::c_void;

use cvt_p;
use error::ErrorStack;

pub struct ConfMethod(*mut c_void);

impl ConfMethod {
    /// Construct from raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the pointer is valid.
    pub unsafe fn from_ptr(ptr: *mut c_void) -> ConfMethod {
        ConfMethod(ptr)
    }

    /// Convert to raw pointer.
    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::CONF;
    fn drop = ffi::NCONF_free;

    pub struct Conf;
    pub struct ConfRef;
}

impl Conf {
    /// Create a configuration parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use openssl::conf::{Conf, ConfMethod};
    ///
    /// let conf = Conf::new(ConfMethod::default());
    /// ```
    pub fn new(method: ConfMethod) -> Result<Conf, ErrorStack> {
        unsafe { cvt_p(ffi::NCONF_new(method.as_ptr())).map(Conf) }
    }
}
