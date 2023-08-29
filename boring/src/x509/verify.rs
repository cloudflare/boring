use crate::ffi;
use foreign_types::ForeignTypeRef;
use libc::c_uint;
use std::net::IpAddr;

use crate::cvt;
use crate::error::ErrorStack;

bitflags! {
    /// Flags used to check an `X509` certificate.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
    pub struct X509CheckFlags: c_uint {
        const ALWAYS_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT as _;
        const NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS as _;
        const NO_PARTIAL_WILDCARDS = ffi::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS as _;
        const MULTI_LABEL_WILDCARDS = ffi::X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS as _;
        const SINGLE_LABEL_SUBDOMAINS = ffi::X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS as _;
        const NEVER_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT as _;

        #[deprecated(since = "0.10.6", note = "renamed to NO_WILDCARDS")]
        const FLAG_NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS as _;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_VERIFY_PARAM;
    fn drop = ffi::X509_VERIFY_PARAM_free;

    /// Adjust parameters associated with certificate verification.
    pub struct X509VerifyParam;
}

impl X509VerifyParamRef {
    /// Set the host flags.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set_hostflags`].
    ///
    /// [`X509_VERIFY_PARAM_set_hostflags`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set_hostflags.html
    pub fn set_hostflags(&mut self, hostflags: X509CheckFlags) {
        unsafe {
            ffi::X509_VERIFY_PARAM_set_hostflags(self.as_ptr(), hostflags.bits());
        }
    }

    /// Set the expected DNS hostname.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set1_host`].
    ///
    /// [`X509_VERIFY_PARAM_set1_host`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set1_host.html
    pub fn set_host(&mut self, host: &str) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set1_host(
                self.as_ptr(),
                host.as_ptr() as *const _,
                host.len(),
            ))
            .map(|_| ())
        }
    }

    /// Set the expected IPv4 or IPv6 address.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set1_ip`].
    ///
    /// [`X509_VERIFY_PARAM_set1_ip`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set1_ip.html
    pub fn set_ip(&mut self, ip: IpAddr) -> Result<(), ErrorStack> {
        unsafe {
            let mut buf = [0; 16];
            let len = match ip {
                IpAddr::V4(addr) => {
                    buf[..4].copy_from_slice(&addr.octets());
                    4
                }
                IpAddr::V6(addr) => {
                    buf.copy_from_slice(&addr.octets());
                    16
                }
            };
            cvt(ffi::X509_VERIFY_PARAM_set1_ip(
                self.as_ptr(),
                buf.as_ptr() as *const _,
                len,
            ))
            .map(|_| ())
        }
    }
}
