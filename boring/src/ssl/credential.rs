#[cfg(feature = "rpk")]
use crate::cvt_p;
use crate::error::ErrorStack;
use crate::pkey::{PKeyRef, Private};
use crate::ssl::callbacks;
use crate::ssl::{PrivateKeyMethod, SslRef};
use crate::{cvt_0i, ffi};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;
#[cfg(feature = "rpk")]
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::SSL_CREDENTIAL;
    fn drop = ffi::SSL_CREDENTIAL_free;
    fn clone = clone_ssl_credential;

    /// A credential.
    pub struct SslCredential;
}

unsafe fn clone_ssl_credential(credential: *mut ffi::SSL_CREDENTIAL) -> *mut ffi::SSL_CREDENTIAL {
    unsafe { ffi::SSL_CREDENTIAL_up_ref(credential) };
    credential
}

impl SslCredential {
    /// Create a credential suitable for a handshake using a raw public key.
    #[corresponds(SSL_CREDENTIAL_new_raw_public_key_empty)]
    #[cfg(feature = "rpk")]
    pub fn new_raw_public_key() -> Result<SslCredentialBuilder, ErrorStack> {
        unsafe {
            Ok(SslCredentialBuilder(Self::from_ptr(cvt_p(
                ffi::SSL_CREDENTIAL_new_raw_public_key_empty(),
            )?)))
        }
    }
}

/// A builder for [`SslCredential`]
pub struct SslCredentialBuilder(SslCredential);

impl SslCredentialBuilder {
    pub(crate) fn as_ptr(&self) -> *mut ffi::SSL_CREDENTIAL {
        self.0.as_ptr()
    }

    // Sets the private key of the credential.
    #[corresponds(SSL_CREDENTIAL_set1_private_key)]
    pub fn set_private_key(&mut self, private_key: &PKeyRef<Private>) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_CREDENTIAL_set1_private_key(
                self.0.as_ptr(),
                private_key.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Configures a custom private key method on the credential.
    ///
    /// See [`PrivateKeyMethod`] for more details.
    #[corresponds(SSL_CREDENTIAL_set_private_key_method)]
    pub fn set_private_key_method<M>(&mut self, method: M) -> Result<(), ErrorStack>
    where
        M: PrivateKeyMethod,
    {
        struct CredentialPrivateKeyMethodSource;

        impl callbacks::PrivateKeyMethodSource for CredentialPrivateKeyMethodSource {
            type Owner = SslCredential;

            fn get_owner(ssl: &SslRef) -> Option<Self::Owner> {
                Some(ssl.selected_credential()?.to_owned())
            }

            fn get_callback(owner: &Self::Owner) -> Option<&dyn PrivateKeyMethod> {
                owner
                    .ownership()
                    .and_then(|ownership| ownership.private_key_method.as_deref())
            }
        }

        unsafe {
            self.try_ownership_mut()?.private_key_method = Some(Box::new(method));

            cvt_0i(ffi::SSL_CREDENTIAL_set_private_key_method(
                self.0.as_ptr(),
                &ffi::SSL_PRIVATE_KEY_METHOD {
                    sign: Some(callbacks::raw_sign::<CredentialPrivateKeyMethodSource>),
                    decrypt: Some(callbacks::raw_decrypt::<CredentialPrivateKeyMethodSource>),
                    complete: Some(callbacks::raw_complete::<CredentialPrivateKeyMethodSource>),
                },
            ))
            .map(|_| ())
        }
    }

    /// Sets the SPKI of the raw public key credential.
    ///
    /// If `spki` is `None`, the SPKI is extracted from the credential's private key.
    #[corresponds(SSL_CREDENTIAL_set1_spki)]
    #[cfg(feature = "rpk")]
    pub fn set_spki_bytes(&mut self, spki: Option<&[u8]>) -> Result<(), ErrorStack> {
        unsafe {
            let spki = spki
                .map(|spki| {
                    cvt_p(ffi::CRYPTO_BUFFER_new(
                        spki.as_ptr(),
                        spki.len(),
                        ptr::null_mut(),
                    ))
                })
                .transpose()?
                .unwrap_or(ptr::null_mut());

            let ret = cvt_0i(ffi::SSL_CREDENTIAL_set1_spki(self.0.as_ptr(), spki)).map(|_| ());

            if !spki.is_null() {
                ffi::CRYPTO_BUFFER_free(spki);
            }

            ret
        }
    }

    #[must_use]
    pub fn build(self) -> SslCredential {
        self.0
    }
}

#[cfg(all(test, feature = "rpk"))]
mod tests {
    use super::*;
    use crate::ec::{EcGroup, EcKey};
    use crate::nid::Nid;
    use crate::pkey::PKey;

    fn generate_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec_key).unwrap()
    }

    fn spki_from_pkey(pkey: &PKey<Private>) -> Vec<u8> {
        pkey.public_key_to_der().unwrap()
    }

    #[test]
    fn set_spki_bytes_none_derives_from_private_key() {
        let key = generate_key();

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        // With a private key set, passing `None` should succeed and derive the
        // SPKI from the private key.
        cred.set_spki_bytes(None).unwrap();
    }

    #[test]
    fn set_spki_bytes_none_without_private_key_fails() {
        let mut cred = SslCredential::new_raw_public_key().unwrap();
        // Without a private key, passing `None` should return an error.
        let err = cred.set_spki_bytes(None).unwrap_err();
        assert!(!err.errors().is_empty());
    }

    #[test]
    fn set_spki_bytes_some_matching_private_key_succeeds() {
        let key = generate_key();
        let spki = spki_from_pkey(&key);

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        cred.set_spki_bytes(Some(&spki)).unwrap();
    }

    #[test]
    fn set_spki_bytes_some_mismatched_private_key_fails() {
        let key = generate_key();
        let other_key = generate_key();
        let wrong_spki = spki_from_pkey(&other_key);

        let mut cred = SslCredential::new_raw_public_key().unwrap();
        cred.set_private_key(&key).unwrap();
        // The public key derived from `wrong_spki` does not match the
        // configured private key, so this must fail.
        let err = cred.set_spki_bytes(Some(&wrong_spki)).unwrap_err();
        assert!(!err.errors().is_empty());
    }
}
