//! Certificate revocation lists describe certificates that have been revoked
//! by their issuer and should no longer be trusted.
//!
//! An `X509CRL` can be provided along with an issuing `X509` to verify that
//! issued certificates have not been revoked.
//!
//! # Example
//!
//! ```rust
//! use boring::hash::MessageDigest;
//! use boring::pkey::{PKey, Private};
//! use boring::x509::crl::{X509CRLBuilder, X509Revoked};
//! use boring::x509::extension::BasicConstraints;
//! use boring::x509::verify::X509VerifyFlags;
//! use boring::x509::X509Extension;
//! use boring::x509::X509;
//! use boring::x509::store::{X509Store, X509StoreBuilder};
//! use boring::asn1::Asn1Time;
//! use boring::bn::BigNum;
//! use boring::error::ErrorStack;
//!
//! fn crl_checking_store(issuer: X509, pkey: PKey<Private>) -> Result<X509Store, ErrorStack> {
//!    let mut builder = X509CRLBuilder::new()?;
//!    builder.set_issuer_name(issuer.subject_name())?;
//!    builder.add_revoked(X509Revoked::from_parts(
//!        &*BigNum::from_u32(1)?.to_asn1_integer()?,
//!        &*Asn1Time::days_from_now(0)?
//!    )?)?;
//!    builder.set_last_update(&*Asn1Time::days_from_now(0)?)?;
//!    builder.set_next_update(&*Asn1Time::days_from_now(30)?)?;
//!    builder.sign(&pkey, MessageDigest::sha256())?;
//!
//!    let mut store_builder = X509StoreBuilder::new()?;
//!    store_builder.add_cert(issuer)?;
//!    store_builder.add_crl(builder.build())?;
//!    store_builder
//!        .param_mut()
//!        .set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;
//!     Ok(store_builder.build())
//! }
//! ```

use crate::asn1::{Asn1BitStringRef, Asn1IntegerRef, Asn1TimeRef};
use crate::foreign_types::ForeignType;
use crate::foreign_types::ForeignTypeRef;
use crate::hash::{DigestBytes, MessageDigest};
use crate::pkey::{HasPrivate, HasPublic, PKeyRef};
use crate::stack::{StackRef, Stackable};
use crate::x509::X509ExtensionRef;
use crate::x509::{X509AlgorithmRef, X509Extension, X509NameRef};
use crate::{cvt, cvt_n, cvt_p, ErrorStack};
use std::convert::TryInto;
use std::fmt::Formatter;
use std::{fmt, mem, ptr};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_REVOKED;
    fn drop = ffi::X509_REVOKED_free;

    /// An `X509_REVOKED` containing information about a revoked certificate
    pub struct X509Revoked;
}

impl Stackable for X509Revoked {
    type StackType = ffi::stack_st_X509_REVOKED;
}

impl X509Revoked {
    /// Create an `X509Revoked`
    ///
    /// This corresponds to [`X509_REVOKED_new`] followed by calls to
    /// [`X509_REVOKED_set_serialNumber`] and [`X509_REVOKED_set_revocationDate`]
    /// with the provided parameters
    ///
    /// [`X509_REVOKED_new`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_new.html
    /// [`X509_REVOKED_set_serialNumber`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_set_serialNumber.html
    /// [`X509_REVOKED_set_revocationDate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_set_revocationDate.html
    pub fn from_parts(
        serial_number: &Asn1IntegerRef,
        revocation_date: &Asn1TimeRef,
    ) -> Result<X509Revoked, ErrorStack> {
        unsafe {
            ffi::init();
            let revoked = cvt_p(ffi::X509_REVOKED_new())?;
            cvt(ffi::X509_REVOKED_set_serialNumber(
                revoked,
                serial_number.as_ptr(),
            ))?;
            cvt(ffi::X509_REVOKED_set_revocationDate(
                revoked,
                revocation_date.as_ptr(),
            ))?;
            Ok(X509Revoked::from_ptr(revoked))
        }
    }
}

impl X509RevokedRef {
    /// Returns the serial number of the revoked certificate
    ///
    /// This corresponds to [`X509_REVOKED_get0_serialNumber`].
    ///
    /// [`X509_REVOKED_get0_serialNumber`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_get0_serialNumber.html
    pub fn serial_number(&self) -> &Asn1IntegerRef {
        unsafe {
            let r = ffi::X509_REVOKED_get0_serialNumber(self.as_ptr());
            assert!(!r.is_null());
            Asn1IntegerRef::from_ptr(r as *mut _)
        }
    }

    /// Returns certificate's revocation date
    ///
    /// This corresponds to [`X509_REVOKED_get0_revocationDate`].
    ///
    /// [`X509_REVOKED_get0_revocationDate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_get0_revocationDate
    pub fn revocation_date(&self) -> &Asn1TimeRef {
        unsafe {
            let date = ffi::X509_REVOKED_get0_revocationDate(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date as *mut _)
        }
    }
}

impl fmt::Debug for X509RevokedRef {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        let sn = self.serial_number().to_bn().and_then(|bn| bn.to_hex_str());
        let sn = sn.as_ref().map(|x| &***x).unwrap_or("");

        fmt.debug_struct("X509Revoked")
            .field("serial_number", &sn)
            .field("revocation_date", self.revocation_date())
            .finish()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_CRL;
    fn drop = ffi::X509_CRL_free;

    /// An `X509CRL` certificate revocation list
    pub struct X509CRL;
}

impl Stackable for X509CRL {
    type StackType = ffi::stack_st_X509_CRL;
}

impl X509CRL {
    from_pem! {
        /// Deserializes a PEM-encoded X509CRL structure.
        ///
        /// The input should have a header of `-----BEGIN X509 CRL-----`
        ///
        /// This corresponds to [`PEM_read_bio_X509_CRL`].
        ///
        /// [`PEM_read_bio_X509_CRL`]: https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_X509_CRL
        from_pem,
        X509CRL,
        ffi::PEM_read_bio_X509_CRL
    }

    from_der! {
       /// Deserializes a DER-encoded X509 structure.
       ///
       /// This corresponds to [`d2i_X509_CRL`].
       ///
       /// [`d2i_X509_CRL`]: https://www.openssl.org/docs/man1.1.1/man3/d2i_X509_CRL.html
        from_der,
        X509CRL,
        ffi::d2i_X509_CRL,
        ::libc::c_long
    }
}

impl X509CRLRef {
    /// Returns the CRL's last update time
    ///
    /// This corresponds to [`X509_CRL_get0_lastUpdate`]
    ///
    /// [`X509_CRL_get0_lastUpdate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_lastUpdate
    pub fn last_update(&self) -> Option<&Asn1TimeRef> {
        unsafe {
            let date = ffi::X509_CRL_get0_lastUpdate(self.as_ptr());
            if date.is_null() {
                None
            } else {
                Some(Asn1TimeRef::from_ptr(date as *mut _))
            }
        }
    }

    /// Returns the CRL's next update time
    ///
    /// This corresponds to [`X509_CRL_get0_nextUpdate`]
    ///
    /// [`X509_CRL_get0_nextUpdate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_nextUpdate
    pub fn next_update(&self) -> Option<&Asn1TimeRef> {
        unsafe {
            let date = ffi::X509_CRL_get0_nextUpdate(self.as_ptr());
            if date.is_null() {
                None
            } else {
                Some(Asn1TimeRef::from_ptr(date as *mut _))
            }
        }
    }

    /// Returns the CRL's issuer name
    ///
    /// This corresponds to [`X509_CRL_get_issuer`]
    ///
    /// [`X509_CRL_get_issuer`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get_issuer
    pub fn issuer(&self) -> &X509NameRef {
        unsafe {
            let name = ffi::X509_CRL_get_issuer(self.as_ptr());

            assert!(!name.is_null());
            X509NameRef::from_ptr(name)
        }
    }

    /// Returns the CRL's extensions
    ///
    /// This corresponds to [`X509_CRL_get0_extensions`]
    ///
    /// [`X509_CRL_get0_extensions`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_extensions
    pub fn extensions(&self) -> Option<&StackRef<X509Extension>> {
        unsafe {
            let extensions = ffi::X509_CRL_get0_extensions(self.as_ptr());
            if extensions.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(extensions as *mut _))
            }
        }
    }

    /// Returns the revoked certificates in this CRL
    ///
    /// This corresponds to [`X509_CRL_get_REVOKED`]
    ///
    /// [`X509_CRL_get_REVOKED`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get_REVOKED
    pub fn revoked(&self) -> Option<&StackRef<X509Revoked>> {
        unsafe {
            let revoked = ffi::X509_CRL_get_REVOKED(self.as_ptr());
            if revoked.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(revoked))
            }
        }
    }

    /// Returns the CRL's signature and signature algorithm
    ///
    /// This corresponds to [`X509_CRL_get0_signature`]
    ///
    /// [`X509_CRL_get0_signature`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_get0_signature
    pub fn signature(&self) -> (&Asn1BitStringRef, &X509AlgorithmRef) {
        unsafe {
            let mut signature = ptr::null();
            let mut algor = ptr::null();
            ffi::X509_CRL_get0_signature(self.as_ptr(), &mut signature, &mut algor);
            assert!(!algor.is_null());
            assert!(!signature.is_null());
            (
                Asn1BitStringRef::from_ptr(signature as *mut _),
                X509AlgorithmRef::from_ptr(algor as *mut _),
            )
        }
    }

    /// Returns a digest of the DER representation of the CRL
    ///
    /// This corresponds to [`X509_CRL_digest`]
    ///
    /// [`X509_CRL_digest`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_digest
    pub fn digest(&self, hash_type: MessageDigest) -> Result<DigestBytes, ErrorStack> {
        unsafe {
            let mut digest = DigestBytes {
                buf: [0; ffi::EVP_MAX_MD_SIZE as usize],
                len: ffi::EVP_MAX_MD_SIZE as usize,
            };
            let mut len = ffi::EVP_MAX_MD_SIZE.try_into().unwrap();
            cvt(ffi::X509_CRL_digest(
                self.as_ptr(),
                hash_type.as_ptr(),
                digest.buf.as_mut_ptr() as *mut _,
                &mut len,
            ))?;
            digest.len = len as usize;

            Ok(digest)
        }
    }

    /// Check if the CRL is signed using the given public key.
    ///
    /// Only the signature is checked: no other checks (such as certificate chain validity)
    /// are performed.
    ///
    /// Returns `true` if verification succeeds.
    ///
    /// This corresponds to [`X509_CRL_verify"].
    ///
    /// [`X509_CRL_verify`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_verify
    pub fn verify<T>(&self, key: &PKeyRef<T>) -> Result<bool, ErrorStack>
    where
        T: HasPublic,
    {
        unsafe { cvt_n(ffi::X509_CRL_verify(self.as_ptr(), key.as_ptr())).map(|n| n != 0) }
    }

    to_pem! {
        /// Serializes the CRL into a PEM-encoded X509 CRL structure.
        ///
        /// The output will have a header of `-----BEGIN X509 CRL-----`
        ///
        /// This corresponds to [`PEM_write_bio_X509_CRL`]
        ///
        /// [`PEM_write_bio_X509_CRL`]: https://www.openssl.org/docs/man1.1.1/man3/PEM_write_bio_X509_CRL
        to_pem,
        ffi::PEM_write_bio_X509_CRL
    }

    to_der! {
        /// Serializes the CRL into a DER-encoded X509 CRL structure
        ///
        /// This corresponds to `i2d_X509_CRL`
        ///
        /// [`i2d_X509_CRL`]: https://www.openssl.org/docs/man1.1.1/man3/i2d_X509_CRL
        to_der,
        ffi::i2d_X509_CRL
    }
}
impl ToOwned for X509CRLRef {
    type Owned = X509CRL;

    fn to_owned(&self) -> X509CRL {
        unsafe {
            ffi::X509_CRL_up_ref(self.as_ptr());
            X509CRL::from_ptr(self.as_ptr())
        }
    }
}

impl Clone for X509CRL {
    fn clone(&self) -> X509CRL {
        X509CRLRef::to_owned(self)
    }
}

impl fmt::Debug for X509CRLRef {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_struct = formatter.debug_struct("X509CRL");
        debug_struct.field("issuer", self.issuer());
        debug_struct.field("signature_algorithm", &self.signature().1.object());

        if let Some(next_update) = self.next_update() {
            debug_struct.field("next_update", next_update);
        }
        if let Some(last_update) = self.last_update() {
            debug_struct.field("last_update", last_update);
        }
        if let Some(revoked) = self.revoked() {
            debug_struct.field("revoked", &revoked);
        }
        if let Some(extensions) = self.extensions() {
            debug_struct.field("extensions", &extensions);
        }
        debug_struct.finish()
    }
}

impl fmt::Debug for X509CRL {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let x: &X509CRLRef = self;
        x.fmt(formatter)
    }
}

/// A builder used to construct an `X509CRL`
pub struct X509CRLBuilder(X509CRL);

impl X509CRLBuilder {
    /// Creates a new builder.
    pub fn new() -> Result<X509CRLBuilder, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_CRL_new()).map(|p| X509CRLBuilder(X509CRL::from_ptr(p)))
        }
    }

    /// Append an `X509Extension` to the certificate revocation list
    ///
    /// This corresponds to [`X509_CRL_add_ext`]
    ///
    /// [`X509_CRL_add_ext`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_add_ext
    pub fn append_extension(&mut self, extension: &X509ExtensionRef) -> Result<(), ErrorStack> {
        unsafe {
            // -1 indicates append to end
            cvt(ffi::X509_CRL_add_ext(
                self.0.as_ptr(),
                extension.as_ptr(),
                -1,
            ))?;
            Ok(())
        }
    }

    /// Signs the certificate revocation list with a private key.
    ///
    /// This corresponds to [`X509_CRL_sign`]
    ///
    /// [`X509_CRL_sign`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_sign
    pub fn sign<T>(&mut self, key: &PKeyRef<T>, hash: MessageDigest) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            cvt(ffi::X509_CRL_sign(
                self.0.as_ptr(),
                key.as_ptr(),
                hash.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Add a revoked certificate to the certificate revocation list
    ///
    /// This corresponds to [`X509_CRL_add0_revoked`]
    ///
    /// [`X509_CRL_add0_revoked`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_add0_revoked
    pub fn add_revoked(&mut self, revoked: X509Revoked) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_add0_revoked(
                self.0.as_ptr(),
                revoked.as_ptr(),
            ))?;
            mem::forget(revoked);
            Ok(())
        }
    }

    /// Sets the issuer name of the certificate revocation list.
    ///
    /// This corresponds to [`X509_CRL_set_issuer_name`]
    ///
    /// [`X509_CRL_set_issuer_name`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_set_issuer_name
    pub fn set_issuer_name(&mut self, issuer_name: &X509NameRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_set_issuer_name(
                self.0.as_ptr(),
                issuer_name.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the version of the certificate revocation list.
    ///
    /// Note that the version is zero-indexed; that is, a certificate corresponding to version 3 of
    /// the X.509 standard should pass `2` to this method.
    ///
    /// This corresponds to [`X509_CRL_set_version`]
    ///
    /// [`X509_CRL_set_version`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_set_version
    pub fn set_version(&mut self, version: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set_version(self.0.as_ptr(), version.into())).map(|_| ()) }
    }

    /// Sets the last update time on the certificate revocation list.
    ///
    /// This corresponds to [`X509_CRL_set1_lastUpdate`]
    ///
    /// [`X509_CRL_set1_lastUpdate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_set1_lastUpdate
    pub fn set_last_update(&mut self, last_update: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_set1_lastUpdate(
                self.0.as_ptr(),
                last_update.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the next update time on the certificate revocation list.
    ///
    /// This corresponds to [`X509_CRL_set1_nextUpdate`]
    ///
    /// [`X509_CRL_set1_nextUpdate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_CRL_set1_nextUpdate
    pub fn set_next_update(&mut self, next_update: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_set1_nextUpdate(
                self.0.as_ptr(),
                next_update.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Consumes the builder, returning the certificate revocation list
    pub fn build(self) -> X509CRL {
        self.0
    }
}
