use crate::ffi;
use foreign_types::ForeignTypeRef;
use libc::{c_uint, time_t};
use std::net::IpAddr;

use crate::cvt;
use crate::error::ErrorStack;

bitflags! {
    /// Flags used to check an `X509` certificate.
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

bitflags! {
    /// Flags used to configure verification of an `X509` certificate
    pub struct X509VerifyFlags: c_uint {
        const CB_ISSUER_CHECK = ffi::X509_V_FLAG_CB_ISSUER_CHECK as _;
        const USE_CHECK_TIME = ffi::X509_V_FLAG_USE_CHECK_TIME as _;
        const CRL_CHECK = ffi::X509_V_FLAG_CRL_CHECK as _;
        const CRL_CHECK_ALL = ffi::X509_V_FLAG_CRL_CHECK_ALL as _;
        const IGNORE_CRITICAL = ffi::X509_V_FLAG_IGNORE_CRITICAL as _;
        const X509_STRICT = ffi::X509_V_FLAG_X509_STRICT as _;
        const ALLOW_PROXY_CERTS = ffi::X509_V_FLAG_ALLOW_PROXY_CERTS as _;
        const POLICY_CHECK = ffi::X509_V_FLAG_POLICY_CHECK as _;
        const EXPLICIT_POLICY = ffi::X509_V_FLAG_EXPLICIT_POLICY as _;
        const INHIBIT_ANY = ffi::X509_V_FLAG_INHIBIT_ANY as _;
        const INHIBIT_MAP = ffi::X509_V_FLAG_INHIBIT_MAP as _;
        const NOTIFY_POLICY = ffi::X509_V_FLAG_NOTIFY_POLICY as _;
        const EXTENDED_CRL_SUPPORT = ffi::X509_V_FLAG_EXTENDED_CRL_SUPPORT as _;
        const FLAG_USE_DELTAS = ffi::X509_V_FLAG_USE_DELTAS as _;
        const CHECK_SS_SIGNATURE = ffi::X509_V_FLAG_CHECK_SS_SIGNATURE as _;
        const TRUSTED_FIRST = ffi::X509_V_FLAG_TRUSTED_FIRST as _;
        const SUITEB_128_LOS_ONLY = ffi::X509_V_FLAG_SUITEB_128_LOS_ONLY as _;
        const SUITEB_192_LOS = ffi::X509_V_FLAG_SUITEB_192_LOS as _;
        const SUITEB_128_LOS = ffi::X509_V_FLAG_SUITEB_128_LOS as _;
        const PARTIAL_CHAIN = ffi::X509_V_FLAG_PARTIAL_CHAIN as _;
        const NO_ALT_CHAINS = ffi::X509_V_FLAG_NO_ALT_CHAINS as _;
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
            ffi::X509_VERIFY_PARAM_set_hostflags(self.as_ptr(), hostflags.bits);
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

    /// Sets the time to check certificates and CRLs against.
    ///
    /// If unset, uses the current time.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set_time`]. Note that BoringSSL does not support
    /// the OpenSSL `NO_CHECK_TIME` option.
    ///
    /// [`X509_VERIFY_PARAM_set_time`]: https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_time.html
    ///
    /// # Example
    ///
    /// ```
    /// use boring::x509::store::X509StoreBuilder;
    /// use std::convert::TryInto;
    /// use std::time::SystemTime;
    ///
    /// let mut store_builder = X509StoreBuilder::new().expect("can create a new builder");
    /// let duration_since_epoch = SystemTime::UNIX_EPOCH.elapsed().expect("it's after 1970");
    /// let seconds_since_epoch: libc::time_t = duration_since_epoch
    ///     .as_secs()
    ///     .try_into()
    ///     .expect("time_t is large enough to represent this time");
    /// store_builder.param_mut().set_time(seconds_since_epoch);
    /// ```
    pub fn set_time(&mut self, unix_time: time_t) {
        unsafe { ffi::X509_VERIFY_PARAM_set_time(self.as_ptr(), unix_time) }
    }

    /// Set the verify flags by OR-ing them with `flags`
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set_flags`].
    ///
    /// [`X509_VERIFY_PARAM_set_flags`]: https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_flags.html
    pub fn set_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set_flags(
                self.as_ptr(),
                flags.bits.into(),
            ))
            .map(|_| ())
        }
    }

    /// Clears the verify flags in `flags`
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_clear_flags`]
    ///
    /// [`X509_VERIFY_PARAM_clear_flags`]: https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_clear_flags.html
    pub fn clear_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_clear_flags(
                self.as_ptr(),
                flags.bits.into(),
            ))
            .map(|_| ())
        }
    }
}
