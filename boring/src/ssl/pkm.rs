use super::callbacks;
use super::{SslContext, SslContextBuilder, SslRef, SslSignatureAlgorithm};
#[cfg(feature = "credential")]
use super::{SslCredential, SslCredentialBuilder};
#[cfg(feature = "credential")]
use crate::cvt_0i;
#[cfg(feature = "credential")]
use crate::error::ErrorStack;
use crate::ffi;
use openssl_macros::corresponds;

/// Describes private key hooks. This is used to off-load signing operations to
/// a custom, potentially asynchronous, backend. Metadata about the key such as
/// the type and size are parsed out of the certificate.
///
/// Corresponds to [`ssl_private_key_method_st`].
///
/// [`ssl_private_key_method_st`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_private_key_method_st
pub trait PrivateKeyMethod: Send + Sync + 'static {
    /// Signs the message `input` using the specified signature algorithm.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// The caller should arrange for the high-level operation on `ssl` to be
    /// retried when the operation is completed. This will result in a call to
    /// [`Self::complete`].
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError>;

    /// Decrypts `input`.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// The caller should arrange for the high-level operation on `ssl` to be
    /// retried when the operation is completed. This will result in a call to
    /// [`Self::complete`].
    ///
    /// This method only works with RSA keys and should perform a raw RSA
    /// decryption operation with no padding.
    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, PrivateKeyMethodError>;

    /// Completes a pending operation.
    ///
    /// On success, it returns `Ok(written)` where `written` is the number of
    /// bytes written into `output`. On failure, it returns
    /// `Err(PrivateKeyMethodError::FAILURE)`. If the operation has not completed,
    /// it returns `Err(PrivateKeyMethodError::RETRY)`.
    ///
    /// This method may be called arbitrarily many times before completion.
    fn complete(&self, ssl: &mut SslRef, output: &mut [u8])
        -> Result<usize, PrivateKeyMethodError>;
}

/// An error returned from a private key method.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrivateKeyMethodError(pub(super) ffi::ssl_private_key_result_t);

impl PrivateKeyMethodError {
    /// A fatal error occurred and the handshake should be terminated.
    pub const FAILURE: Self = Self(ffi::ssl_private_key_result_t::ssl_private_key_failure);

    /// The operation could not be completed and should be retried later.
    pub const RETRY: Self = Self(ffi::ssl_private_key_result_t::ssl_private_key_retry);
}

macro_rules! pkm {
    (
        source = $source:ident,
        owner = $owner:ty,
        builder = $builder:ty,
        corresponds = $corresponds:ident,
        get_owner = |$ssl:ident| $get_owner:expr,
        get_callback = |$owner_ref:ident| $get_callback:expr,
        set = |$this:ident, $method:ident, $table:ident| $(-> $result:ty)? $set:block,
    ) => {
        struct $source;

        impl callbacks::PrivateKeyMethodSource for $source {
            type Owner = $owner;

            fn get_owner($ssl: &SslRef) -> Option<Self::Owner> {
                ($get_owner).map(ToOwned::to_owned)
            }

            fn get_callback($owner_ref: &Self::Owner) -> Option<&dyn PrivateKeyMethod> {
                $get_callback
            }
        }

        impl $builder {
            /// Configures a custom private key method.
            ///
            /// See [`PrivateKeyMethod`] for more details.
            #[corresponds($corresponds)]
            pub fn set_private_key_method<M>(&mut self, method: M) $(-> $result)?
            where
                M: PrivateKeyMethod,
            {
                let $this = self;
                let $method = method;
                let $table = &ffi::SSL_PRIVATE_KEY_METHOD {
                    sign: Some(callbacks::raw_sign::<$source>),
                    decrypt: Some(callbacks::raw_decrypt::<$source>),
                    complete: Some(callbacks::raw_complete::<$source>),
                };

                $set
            }
        }
    };
}

pkm!(
    source = ContextPrivateKeyMethodSource,
    owner = SslContext,
    builder = SslContextBuilder,
    corresponds = SSL_CTX_set_private_key_method,
    get_owner = |ssl| Some(ssl.ssl_context()),
    get_callback = |owner| owner
        .callbacks()
        .and_then(|callbacks| callbacks.private_key_method.as_deref()),
    set = |builder, method, table| {
        builder.callbacks_mut().private_key_method = Some(Box::new(method));

        unsafe {
            ffi::SSL_CTX_set_private_key_method(builder.as_ptr(), table);
        }
    },
);

#[cfg(feature = "credential")]
pkm!(
    source = CredentialPrivateKeyMethodSource,
    owner = SslCredential,
    builder = SslCredentialBuilder,
    corresponds = SSL_CREDENTIAL_set_private_key_method,
    get_owner = |ssl| ssl.selected_credential(),
    get_callback = |owner| owner
        .ownership()
        .and_then(|ownership| ownership.private_key_method.as_deref()),
    set = |builder, method, table| -> Result<(), ErrorStack> {
        builder.try_ownership_mut()?.private_key_method = Some(Box::new(method));

        unsafe {
            cvt_0i(ffi::SSL_CREDENTIAL_set_private_key_method(
                builder.as_ptr(),
                table,
            ))?;
        }
        Ok(())
    },
);
