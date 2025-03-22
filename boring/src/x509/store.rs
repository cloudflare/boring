//! Describe a context in which to verify an `X509` certificate.
//!
//! The `X509` certificate store holds trusted CA certificates used to verify
//! peer certificates.
//!
//! # Example
//!
//! ```rust
//! use boring::x509::store::{X509StoreBuilder, X509Store};
//! use boring::x509::{X509, X509Name};
//! use boring::asn1::Asn1Time;
//! use boring::pkey::PKey;
//! use boring::hash::MessageDigest;
//! use boring::rsa::Rsa;
//! use boring::nid::Nid;
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let pkey = PKey::from_rsa(rsa).unwrap();
//! let mut name = X509Name::builder().unwrap();
//!
//! name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com").unwrap();
//!
//! let name = name.build();
//! let mut builder = X509::builder().unwrap();
//!
//! // Sep 27th, 2016
//! let sample_time = Asn1Time::from_unix(1474934400).unwrap();
//!
//! builder.set_version(2).unwrap();
//! builder.set_subject_name(&name).unwrap();
//! builder.set_issuer_name(&name).unwrap();
//! builder.set_pubkey(&pkey).unwrap();
//! builder.set_not_before(&sample_time);
//! builder.set_not_after(&sample_time);
//! builder.sign(&pkey, MessageDigest::sha256()).unwrap();
//!
//! let certificate: X509 = builder.build();
//! let mut builder = X509StoreBuilder::new().unwrap();
//! let _ = builder.add_cert(certificate);
//! let store: X509Store = builder.build();
//! ```

use crate::error::ErrorStack;
use crate::ffi;
use crate::stack::StackRef;
use crate::x509::verify::{X509VerifyFlags, X509VerifyParamRef};
use crate::x509::{X509Object, X509};
use crate::{cvt, cvt_p};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
use std::mem;

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A builder type used to construct an `X509Store`.
    pub struct X509StoreBuilder;
}

impl X509StoreBuilder {
    /// Returns a builder for a certificate store.
    ///
    /// The store is initially empty.
    pub fn new() -> Result<X509StoreBuilder, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::X509_STORE_new()).map(|p| X509StoreBuilder::from_ptr(p))
        }
    }

    /// Constructs the `X509Store`.
    pub fn build(self) -> X509Store {
        let store = X509Store(self.0);
        mem::forget(self);
        store
    }
}

impl X509StoreBuilderRef {
    /// Adds a certificate to the certificate store.
    // FIXME should take an &X509Ref
    #[corresponds(X509_STORE_add_cert)]
    pub fn add_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    #[corresponds(X509_STORE_set_default_paths)]
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())).map(|_| ()) }
    }

    /// Sets certificate chain validation related flags.
    #[corresponds(X509_STORE_set_flags)]
    pub fn set_flags(&mut self, flags: X509VerifyFlags) {
        unsafe {
            cvt(ffi::X509_STORE_set_flags(self.as_ptr(), flags.bits())).unwrap();
        }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    #[corresponds(X509_STORE_get0_param)]
    pub fn verify_param_mut(&mut self) -> &mut X509VerifyParamRef {
        unsafe { X509VerifyParamRef::from_ptr_mut(ffi::X509_STORE_get0_param(self.as_ptr())) }
    }

    /// Sets certificate chain validation related parameters.
    #[corresponds(X509_STORE_set1_param)]
    pub fn set_param(&mut self, param: &X509VerifyParamRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set1_param(self.as_ptr(), param.as_ptr())).map(|_| ()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A certificate store to hold trusted `X509` certificates.
    pub struct X509Store;
}

impl Clone for X509Store {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl ToOwned for X509StoreRef {
    type Owned = X509Store;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            ffi::X509_STORE_up_ref(self.as_ptr());
            X509Store::from_ptr(self.as_ptr())
        }
    }
}

impl X509StoreRef {
    /// **Warning: this method is unsound**
    ///
    /// Get a reference to the cache of certificates in this store.
    ///
    /// # Safety
    /// References may be invalidated by any access to the shared cache.
    #[deprecated(
        note = "This method is unsound https://github.com/sfackler/rust-openssl/issues/2096"
    )]
    #[corresponds(X509_STORE_get0_objects)]
    pub fn objects(&self) -> &StackRef<X509Object> {
        unsafe { StackRef::from_ptr(ffi::X509_STORE_get0_objects(self.as_ptr())) }
    }

    /// For testing only, where it doesn't have to expose an unsafe pointer
    #[cfg(test)]
    #[allow(deprecated)]
    pub fn objects_len(&self) -> usize {
        self.objects().len()
    }
}
