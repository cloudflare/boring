//! FIPS 140-2 support.
//!
//! See [OpenSSL's documentation] for details.
//!
//! [OpenSSL's documentation]: https://www.openssl.org/docs/fips/UserGuide-2.0.pdf
use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;

/// Moves the library into or out of the FIPS 140-2 mode of operation.
///
/// This corresponds to `FIPS_mode_set`.
pub fn enable(enabled: bool) -> Result<(), ErrorStack> {
    unsafe { cvt(ffi::FIPS_mode_set(enabled as _)).map(|_| ()) }
}

/// Determines if the library is running in the FIPS 140-2 mode of operation.
///
/// This corresponds to `FIPS_mode`.
pub fn enabled() -> bool {
    unsafe { ffi::FIPS_mode() != 0 }
}

#[test]
fn is_enabled() {
    #[cfg(any(feature = "fips", feature = "fips-link-precompiled"))]
    assert!(enabled());
    #[cfg(not(any(feature = "fips", feature = "fips-link-precompiled")))]
    assert!(!enabled());
}
