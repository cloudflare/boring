#![deny(missing_docs)]

//! Defines the format of certificiates
//!
//! This module is used by [`x509`] and other certificate building functions
//! to describe time, strings, and objects.
//!
//! Abstract Syntax Notation One is an interface description language.
//! The specification comes from [X.208] by OSI, and rewritten in X.680.
//! ASN.1 describes properties of an object with a type set.  Those types
//! can be atomic, structured, choice, and other (CHOICE and ANY).  These
//! types are expressed as a number and the assignment operator ::=  gives
//! the type a name.
//!
//! The implementation here provides a subset of the ASN.1 types that OpenSSL
//! uses, especially in the properties of a certificate used in HTTPS.
//!
//! [X.208]: https://www.itu.int/rec/T-REC-X.208-198811-W/en
//! [`x509`]: ../x509/struct.X509Builder.html
//!
//! ## Examples
//!
//! ```
//! use boring::asn1::Asn1Time;
//! let tomorrow = Asn1Time::days_from_now(1);
//! ```
use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_int, c_long, time_t};
use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use crate::bio::MemBio;
use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::string::OpensslString;
use crate::{cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_GENERALIZEDTIME;
    fn drop = ffi::ASN1_GENERALIZEDTIME_free;

    /// Non-UTC representation of time
    ///
    /// If a time can be represented by UTCTime, UTCTime is used
    /// otherwise, ASN1_GENERALIZEDTIME is used.  This would be, for
    /// example outside the year range of 1950-2049.
    ///
    /// [ASN1_GENERALIZEDTIME_set] documentation from OpenSSL provides
    /// further details of implmentation.  Note: these docs are from the master
    /// branch as documentation on the 1.1.0 branch did not include this page.
    ///
    /// [ASN1_GENERALIZEDTIME_set]: https://www.openssl.org/docs/manmaster/man3/ASN1_GENERALIZEDTIME_set.html
    pub struct Asn1GeneralizedTime;
    /// Reference to a [`Asn1GeneralizedTime`]
    ///
    /// [`Asn1GeneralizedTime`]: struct.Asn1GeneralizedTime.html
    pub struct Asn1GeneralizedTimeRef;
}

impl fmt::Display for Asn1GeneralizedTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = match MemBio::new() {
                Err(_) => return f.write_str("error"),
                Ok(m) => m,
            };
            let print_result = cvt(ffi::ASN1_GENERALIZEDTIME_print(
                mem_bio.as_ptr(),
                self.as_ptr(),
            ));
            match print_result {
                Err(_) => f.write_str("error"),
                Ok(_) => f.write_str(str::from_utf8_unchecked(mem_bio.get_buf())),
            }
        }
    }
}

/// Difference between two ASN1 times.
///
/// This `struct` is created by the [`diff`] method on [`Asn1TimeRef`]. See its
/// documentation for more.
///
/// [`diff`]: struct.Asn1TimeRef.html#method.diff
/// [`Asn1TimeRef`]: struct.Asn1TimeRef.html
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TimeDiff {
    /// Difference in days
    pub days: c_int,
    /// Difference in seconds.
    ///
    /// This is always less than the number of seconds in a day.
    pub secs: c_int,
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_TIME;
    fn drop = ffi::ASN1_TIME_free;
    /// Time storage and comparison
    ///
    /// Asn1Time should be used to store and share time information
    /// using certificates.  If Asn1Time is set using a string, it must
    /// be in either YYMMDDHHMMSSZ, YYYYMMDDHHMMSSZ, or another ASN.1 format.
    ///
    /// [ASN_TIME_set] documentation at OpenSSL explains the ASN.1 implementation
    /// used by OpenSSL.
    ///
    /// [ASN_TIME_set]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_TIME_set.html
    pub struct Asn1Time;
    /// Reference to an [`Asn1Time`]
    ///
    /// [`Asn1Time`]: struct.Asn1Time.html
    pub struct Asn1TimeRef;
}

impl Asn1TimeRef {
    /// Find difference between two times
    ///
    /// This corresponds to [`ASN1_TIME_diff`].
    ///
    /// [`ASN1_TIME_diff`]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_TIME_diff.html
    pub fn diff(&self, compare: &Self) -> Result<TimeDiff, ErrorStack> {
        let mut days = 0;
        let mut secs = 0;
        let other = compare.as_ptr();

        let err = unsafe { ffi::ASN1_TIME_diff(&mut days, &mut secs, self.as_ptr(), other) };

        match err {
            0 => Err(ErrorStack::get()),
            _ => Ok(TimeDiff { days, secs }),
        }
    }

    /// Compare two times
    ///
    /// This corresponds to [`ASN1_TIME_compare`] but is implemented using [`diff`] so that it is
    /// also supported on older versions of OpenSSL.
    ///
    /// [`ASN1_TIME_compare`]: https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_compare.html
    /// [`diff`]: struct.Asn1TimeRef.html#method.diff
    pub fn compare(&self, other: &Self) -> Result<Ordering, ErrorStack> {
        let d = self.diff(other)?;
        if d.days > 0 || d.secs > 0 {
            return Ok(Ordering::Less);
        }
        if d.days < 0 || d.secs < 0 {
            return Ok(Ordering::Greater);
        }

        Ok(Ordering::Equal)
    }
}

impl PartialEq for Asn1TimeRef {
    fn eq(&self, other: &Asn1TimeRef) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl PartialEq<Asn1Time> for Asn1TimeRef {
    fn eq(&self, other: &Asn1Time) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl<'a> PartialEq<Asn1Time> for &'a Asn1TimeRef {
    fn eq(&self, other: &Asn1Time) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl PartialOrd for Asn1TimeRef {
    fn partial_cmp(&self, other: &Asn1TimeRef) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl PartialOrd<Asn1Time> for Asn1TimeRef {
    fn partial_cmp(&self, other: &Asn1Time) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl<'a> PartialOrd<Asn1Time> for &'a Asn1TimeRef {
    fn partial_cmp(&self, other: &Asn1Time) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl fmt::Display for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = match MemBio::new() {
                Err(_) => return f.write_str("error"),
                Ok(m) => m,
            };
            let print_result = cvt(ffi::ASN1_TIME_print(mem_bio.as_ptr(), self.as_ptr()));
            match print_result {
                Err(_) => f.write_str("error"),
                Ok(_) => f.write_str(str::from_utf8_unchecked(mem_bio.get_buf())),
            }
        }
    }
}

impl fmt::Debug for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl Asn1Time {
    fn new() -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = cvt_p(ffi::ASN1_TIME_new())?;
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    fn from_period(period: c_long) -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = cvt_p(ffi::X509_gmtime_adj(ptr::null_mut(), period))?;
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, ErrorStack> {
        Asn1Time::from_period(days as c_long * 60 * 60 * 24)
    }

    /// Creates a new time from the specified `time_t` value
    pub fn from_unix(time: time_t) -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = cvt_p(ffi::ASN1_TIME_set(ptr::null_mut(), time))?;
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    /// Creates a new time corresponding to the specified ASN1 time string.
    ///
    /// This corresponds to [`ASN1_TIME_set_string`].
    ///
    /// [`ASN1_TIME_set_string`]: https://www.openssl.org/docs/manmaster/man3/ASN1_TIME_set_string.html
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Asn1Time, ErrorStack> {
        unsafe {
            let s = CString::new(s).unwrap();

            let time = Asn1Time::new()?;
            cvt(ffi::ASN1_TIME_set_string(time.as_ptr(), s.as_ptr()))?;

            Ok(time)
        }
    }
}

impl PartialEq for Asn1Time {
    fn eq(&self, other: &Asn1Time) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl PartialEq<Asn1TimeRef> for Asn1Time {
    fn eq(&self, other: &Asn1TimeRef) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl<'a> PartialEq<&'a Asn1TimeRef> for Asn1Time {
    fn eq(&self, other: &&'a Asn1TimeRef) -> bool {
        self.diff(other)
            .map(|t| t.days == 0 && t.secs == 0)
            .unwrap_or(false)
    }
}

impl PartialOrd for Asn1Time {
    fn partial_cmp(&self, other: &Asn1Time) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl PartialOrd<Asn1TimeRef> for Asn1Time {
    fn partial_cmp(&self, other: &Asn1TimeRef) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

impl<'a> PartialOrd<&'a Asn1TimeRef> for Asn1Time {
    fn partial_cmp(&self, other: &&'a Asn1TimeRef) -> Option<Ordering> {
        self.compare(other).ok()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_STRING;
    fn drop = ffi::ASN1_STRING_free;
    /// Primary ASN.1 type used by OpenSSL
    ///
    /// Almost all ASN.1 types in OpenSSL are represented by ASN1_STRING
    /// structures.  This implementation uses [ASN1_STRING-to_UTF8] to preserve
    /// compatibility with Rust's String.
    ///
    /// [ASN1_STRING-to_UTF8]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_STRING_to_UTF8.html
    pub struct Asn1String;
    /// Reference to [`Asn1String`]
    ///
    /// [`Asn1String`]: struct.Asn1String.html
    pub struct Asn1StringRef;
}

impl Asn1StringRef {
    /// Converts the ASN.1 underlying format to UTF8
    ///
    /// ASN.1 strings may utilize UTF-16, ASCII, BMP, or UTF8.  This is important to
    /// consume the string in a meaningful way without knowing the underlying
    /// format.
    pub fn as_utf8(&self) -> Result<OpensslString, ErrorStack> {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = ffi::ASN1_STRING_to_UTF8(&mut ptr, self.as_ptr());
            if len < 0 {
                return Err(ErrorStack::get());
            }

            Ok(OpensslString::from_ptr(ptr as *mut c_char))
        }
    }

    /// Return the string as an array of bytes.
    ///
    /// The bytes do not directly correspond to UTF-8 encoding.  To interact with
    /// strings in rust, it is preferable to use [`as_utf8`]
    ///
    /// [`as_utf8`]: struct.Asn1String.html#method.as_utf8
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_get0_data(self.as_ptr()), self.len()) }
    }

    /// Returns the number of bytes in the string.
    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr()) as usize }
    }

    /// Determines if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for Asn1StringRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.as_utf8() {
            Ok(openssl_string) => openssl_string.fmt(fmt),
            Err(_) => fmt.write_str("error"),
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_INTEGER;
    fn drop = ffi::ASN1_INTEGER_free;

    /// Numeric representation
    ///
    /// Integers in ASN.1 may include BigNum, int64 or uint64.  BigNum implementation
    /// can be found within [`bn`] module.
    ///
    /// OpenSSL documentation includes [`ASN1_INTEGER_set`].
    ///
    /// [`bn`]: ../bn/index.html
    /// [`ASN1_INTEGER_set`]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_INTEGER_set.html
    pub struct Asn1Integer;
    /// Reference to [`Asn1Integer`]
    ///
    /// [`Asn1Integer`]: struct.Asn1Integer.html
    pub struct Asn1IntegerRef;
}

impl Asn1Integer {
    /// Converts a bignum to an `Asn1Integer`.
    ///
    /// Corresponds to [`BN_to_ASN1_INTEGER`]. Also see
    /// [`BigNumRef::to_asn1_integer`].
    ///
    /// [`BN_to_ASN1_INTEGER`]: https://www.openssl.org/docs/man1.1.0/crypto/BN_to_ASN1_INTEGER.html
    /// [`BigNumRef::to_asn1_integer`]: ../bn/struct.BigNumRef.html#method.to_asn1_integer
    pub fn from_bn(bn: &BigNumRef) -> Result<Self, ErrorStack> {
        bn.to_asn1_integer()
    }
}

impl Asn1IntegerRef {
    #[allow(missing_docs)]
    #[deprecated(since = "0.10.6", note = "use to_bn instead")]
    pub fn get(&self) -> i64 {
        unsafe { crate::ffi::ASN1_INTEGER_get(self.as_ptr()) as i64 }
    }

    /// Converts the integer to a `BigNum`.
    ///
    /// This corresponds to [`ASN1_INTEGER_to_BN`].
    ///
    /// [`ASN1_INTEGER_to_BN`]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_INTEGER_get.html
    pub fn to_bn(&self) -> Result<BigNum, ErrorStack> {
        unsafe {
            cvt_p(crate::ffi::ASN1_INTEGER_to_BN(
                self.as_ptr(),
                ptr::null_mut(),
            ))
            .map(|p| BigNum::from_ptr(p))
        }
    }

    /// Sets the ASN.1 value to the value of a signed 32-bit integer, for larger numbers
    /// see [`bn`].
    ///
    /// OpenSSL documentation at [`ASN1_INTEGER_set`]
    ///
    /// [`bn`]: ../bn/struct.BigNumRef.html#method.to_asn1_integer
    /// [`ASN1_INTEGER_set`]: https://www.openssl.org/docs/man1.1.0/crypto/ASN1_INTEGER_set.html
    pub fn set(&mut self, value: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(crate::ffi::ASN1_INTEGER_set(self.as_ptr(), value as c_long)).map(|_| ()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_BIT_STRING;
    fn drop = ffi::ASN1_BIT_STRING_free;
    /// Sequence of bytes
    ///
    /// Asn1BitString is used in [`x509`] certificates for the signature.
    /// The bit string acts as a collection of bytes.
    ///
    /// [`x509`]: ../x509/struct.X509.html#method.signature
    pub struct Asn1BitString;
    /// Reference to [`Asn1BitString`]
    ///
    /// [`Asn1BitString`]: struct.Asn1BitString.html
    pub struct Asn1BitStringRef;
}

impl Asn1BitStringRef {
    /// Returns the Asn1BitString as a slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_get0_data(self.as_ptr() as *mut _), self.len()) }
    }

    /// Returns the number of bytes in the string.
    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr() as *const _) as usize }
    }

    /// Determines if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::ASN1_OBJECT;
    fn drop = ffi::ASN1_OBJECT_free;

    /// Object Identifier
    ///
    /// Represents an ASN.1 Object.  Typically, NIDs, or numeric identifiers
    /// are stored as a table within the [`Nid`] module.  These constants are
    /// used to determine attributes of a certificate, such as mapping the
    /// attribute "CommonName" to "CN" which is represented as the OID of 13.
    /// This attribute is a constant in the [`nid::COMMONNAME`].
    ///
    /// OpenSSL documentation at [`OBJ_nid2obj`]
    ///
    /// [`Nid`]: ../nid/index.html
    /// [`nid::COMMONNAME`]: ../nid/constant.COMMONNAME.html
    /// [`OBJ_nid2obj`]: https://www.openssl.org/docs/man1.1.0/crypto/OBJ_obj2nid.html
    pub struct Asn1Object;
    /// Reference to [`Asn1Object`]
    ///
    /// [`Asn1Object`]: struct.Asn1Object.html
    pub struct Asn1ObjectRef;
}

impl Asn1Object {
    /// Constructs an ASN.1 Object Identifier from a string representation of
    /// the OID.
    ///
    /// This corresponds to [`OBJ_txt2obj`].
    ///
    /// [`OBJ_txt2obj`]: https://www.openssl.org/docs/man1.1.0/man3/OBJ_txt2obj.html
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(txt: &str) -> Result<Asn1Object, ErrorStack> {
        unsafe {
            ffi::init();
            let txt = CString::new(txt).unwrap();
            let obj: *mut ffi::ASN1_OBJECT = cvt_p(ffi::OBJ_txt2obj(txt.as_ptr() as *const _, 0))?;
            Ok(Asn1Object::from_ptr(obj))
        }
    }
}

impl Asn1ObjectRef {
    /// Returns the NID associated with this OID.
    pub fn nid(&self) -> Nid {
        unsafe { Nid::from_raw(ffi::OBJ_obj2nid(self.as_ptr())) }
    }
}

impl fmt::Display for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mut buf = [0; 80];
            let len = ffi::OBJ_obj2txt(
                buf.as_mut_ptr() as *mut _,
                buf.len() as c_int,
                self.as_ptr(),
                0,
            );
            match str::from_utf8(&buf[..len as usize]) {
                Err(_) => fmt.write_str("error"),
                Ok(s) => fmt.write_str(s),
            }
        }
    }
}

impl fmt::Debug for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.to_string().as_str())
    }
}

use crate::ffi::ASN1_STRING_get0_data;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::BigNum;
    use crate::nid::Nid;

    /// Tests conversion between BigNum and Asn1Integer.
    #[test]
    fn bn_cvt() {
        fn roundtrip(bn: BigNum) {
            let large = Asn1Integer::from_bn(&bn).unwrap();
            assert_eq!(large.to_bn().unwrap(), bn);
        }

        roundtrip(BigNum::from_dec_str("1000000000000000000000000000000000").unwrap());
        roundtrip(-BigNum::from_dec_str("1000000000000000000000000000000000").unwrap());
        roundtrip(BigNum::from_u32(1234).unwrap());
        roundtrip(-BigNum::from_u32(1234).unwrap());
    }

    #[test]
    fn time_from_str() {
        Asn1Time::from_str("99991231235959Z").unwrap();
    }

    #[test]
    fn time_from_unix() {
        let t = Asn1Time::from_unix(0).unwrap();
        assert_eq!("Jan  1 00:00:00 1970 GMT", t.to_string());
    }

    #[test]
    fn time_eq() {
        let a = Asn1Time::from_str("99991231235959Z").unwrap();
        let b = Asn1Time::from_str("99991231235959Z").unwrap();
        let c = Asn1Time::from_str("99991231235958Z").unwrap();
        let a_ref = a.as_ref();
        let b_ref = b.as_ref();
        let c_ref = c.as_ref();
        assert!(a == b);
        assert!(a != c);
        assert!(a == b_ref);
        assert!(a != c_ref);
        assert!(b_ref == a);
        assert!(c_ref != a);
        assert!(a_ref == b_ref);
        assert!(a_ref != c_ref);
    }

    #[test]
    fn time_ord() {
        let a = Asn1Time::from_str("99991231235959Z").unwrap();
        let b = Asn1Time::from_str("99991231235959Z").unwrap();
        let c = Asn1Time::from_str("99991231235958Z").unwrap();
        let a_ref = a.as_ref();
        let b_ref = b.as_ref();
        let c_ref = c.as_ref();
        assert!(a >= b);
        assert!(a > c);
        assert!(b <= a);
        assert!(c < a);

        assert!(a_ref >= b);
        assert!(a_ref > c);
        assert!(b_ref <= a);
        assert!(c_ref < a);

        assert!(a >= b_ref);
        assert!(a > c_ref);
        assert!(b <= a_ref);
        assert!(c < a_ref);

        assert!(a_ref >= b_ref);
        assert!(a_ref > c_ref);
        assert!(b_ref <= a_ref);
        assert!(c_ref < a_ref);
    }

    #[test]
    fn object_from_str() {
        let object = Asn1Object::from_str("2.16.840.1.101.3.4.2.1").unwrap();
        assert_eq!(object.nid(), Nid::SHA256);
    }

    #[test]
    fn object_from_str_with_invalid_input() {
        Asn1Object::from_str("NOT AN OID")
            .map(|object| object.to_string())
            .expect_err("parsing invalid OID should fail");
    }
}
