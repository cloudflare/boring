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
//! builder.set_version(2).unwrap();
//! builder.set_subject_name(&name).unwrap();
//! builder.set_issuer_name(&name).unwrap();
//! builder.set_pubkey(&pkey).unwrap();
//! builder.sign(&pkey, MessageDigest::sha256()).unwrap();
//!
//! let certificate: X509 = builder.build();
//! let mut builder = X509StoreBuilder::new().unwrap();
//! let _ = builder.add_cert(certificate);
//! let store: X509Store = builder.build();
//! ```

use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::mem;

use crate::error::ErrorStack;
use crate::stack::StackRef;
use crate::x509::crl::X509CRL;
use crate::x509::verify::X509VerifyParamRef;
use crate::x509::{X509Object, X509};
use crate::{cvt, cvt_p};

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
    pub fn add_cert(&mut self, cert: X509) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Adds a CRL to the certificate store.
    ///
    /// This corresponds to [`X509_STORE_add_crl`].
    ///
    /// [`X509_STORE_add_crl`]: https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_add_crl
    pub fn add_crl(&mut self, crl: X509CRL) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_crl(self.as_ptr(), crl.as_ptr())).map(|_| ()) }
    }

    /// Returns a mutable reference to the X509 verification configuration.
    ///
    /// This corresponds to [`X509_STORE_get0_param`].
    ///
    /// [`X509_STORE_add_crl`]: https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_get0_param
    pub fn param_mut(&mut self) -> &mut X509VerifyParamRef {
        unsafe { X509VerifyParamRef::from_ptr_mut(ffi::X509_STORE_get0_param(self.as_ptr())) }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())).map(|_| ()) }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A certificate store to hold trusted `X509` certificates.
    pub struct X509Store;
}

impl X509StoreRef {
    /// Get a reference to the cache of certificates in this store.
    pub fn objects(&self) -> &StackRef<X509Object> {
        unsafe { StackRef::from_ptr(X509_STORE_get0_objects(self.as_ptr())) }
    }
}

use crate::ffi::X509_STORE_get0_objects;
