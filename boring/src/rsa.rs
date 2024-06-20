//! Rivest–Shamir–Adleman cryptosystem
//!
//! RSA is one of the earliest asymmetric public key encryption schemes.
//! Like many other cryptosystems, RSA relies on the presumed difficulty of a hard
//! mathematical problem, namely factorization of the product of two large prime
//! numbers. At the moment there does not exist an algorithm that can factor such
//! large numbers in reasonable time. RSA is used in a wide variety of
//! applications including digital signatures and key exchanges such as
//! establishing a TLS/SSL connection.
//!
//! The RSA acronym is derived from the first letters of the surnames of the
//! algorithm's founding trio.
//!
//! # Example
//!
//! Generate a 2048-bit RSA key pair and use the public key to encrypt some data.
//!
//! ```rust
//! use boring::rsa::{Rsa, Padding};
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let data = b"foobar";
//! let mut buf = vec![0; rsa.size() as usize];
//! let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
//! ```
use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::fmt;
use std::mem;
use std::ptr;

use crate::bn::{BigNum, BigNumRef};
use crate::error::ErrorStack;
use crate::pkey::{HasPrivate, HasPublic, Private, Public};
use crate::{cvt, cvt_n, cvt_p};

pub const EVP_PKEY_OP_SIGN: c_int = 1 << 3;
pub const EVP_PKEY_OP_VERIFY: c_int = 1 << 4;
pub const EVP_PKEY_OP_VERIFYRECOVER: c_int = 1 << 5;
pub const EVP_PKEY_OP_SIGNCTX: c_int = 1 << 6;
pub const EVP_PKEY_OP_VERIFYCTX: c_int = 1 << 7;
pub const EVP_PKEY_OP_ENCRYPT: c_int = 1 << 8;
pub const EVP_PKEY_OP_DECRYPT: c_int = 1 << 9;

pub const EVP_PKEY_OP_TYPE_SIG: c_int = EVP_PKEY_OP_SIGN
    | EVP_PKEY_OP_VERIFY
    | EVP_PKEY_OP_VERIFYRECOVER
    | EVP_PKEY_OP_SIGNCTX
    | EVP_PKEY_OP_VERIFYCTX;

pub const EVP_PKEY_OP_TYPE_CRYPT: c_int = EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT;

/// Type of encryption padding to use.
///
/// Random length padding is primarily used to prevent attackers from
/// predicting or knowing the exact length of a plaintext message that
/// can possibly lead to breaking encryption.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Padding(c_int);

impl Padding {
    pub const NONE: Padding = Padding(ffi::RSA_NO_PADDING);
    pub const PKCS1: Padding = Padding(ffi::RSA_PKCS1_PADDING);
    pub const PKCS1_OAEP: Padding = Padding(ffi::RSA_PKCS1_OAEP_PADDING);
    pub const PKCS1_PSS: Padding = Padding(ffi::RSA_PKCS1_PSS_PADDING);

    /// Creates a `Padding` from an integer representation.
    pub fn from_raw(value: c_int) -> Padding {
        Padding(value)
    }

    /// Returns the integer representation of `Padding`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::RSA;
    fn drop = ffi::RSA_free;

    /// An RSA key.
    pub struct Rsa<T>;

    /// Reference to `RSA`
    pub struct RsaRef<T>;
}

impl<T> Clone for Rsa<T> {
    fn clone(&self) -> Rsa<T> {
        (**self).to_owned()
    }
}

impl<T> ToOwned for RsaRef<T> {
    type Owned = Rsa<T>;

    fn to_owned(&self) -> Rsa<T> {
        unsafe {
            ffi::RSA_up_ref(self.as_ptr());
            Rsa::from_ptr(self.as_ptr())
        }
    }
}

impl<T> RsaRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
        ///
        /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPrivateKey`].
        ///
        /// [`PEM_write_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_RSAPrivateKey.html
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_RSAPrivateKey
    }

    to_der! {
        /// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`i2d_RSAPrivateKey`].
        ///
        /// [`i2d_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPrivateKey.html
        private_key_to_der,
        ffi::i2d_RSAPrivateKey
    }

    /// Decrypts data using the private key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_decrypt(
                from.len(),
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the private key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `self` has no private components, or if `to` is smaller
    /// than `self.size()`.
    pub fn private_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_private_encrypt(
                from.len(),
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the private exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn d(&self) -> &BigNumRef {
        unsafe {
            let mut d = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut d);
            BigNumRef::from_ptr(d as *mut _)
        }
    }

    /// Returns a reference to the first factor of the exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_factors`].
    ///
    /// [`RSA_get0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn p(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut p = ptr::null();
            RSA_get0_factors(self.as_ptr(), &mut p, ptr::null_mut());
            if p.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(p as *mut _))
            }
        }
    }

    /// Returns a reference to the second factor of the exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_factors`].
    ///
    /// [`RSA_get0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn q(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut q = ptr::null();
            RSA_get0_factors(self.as_ptr(), ptr::null_mut(), &mut q);
            if q.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(q as *mut _))
            }
        }
    }

    /// Returns a reference to the first exponent used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn dmp1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dp = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), &mut dp, ptr::null_mut(), ptr::null_mut());
            if dp.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dp as *mut _))
            }
        }
    }

    /// Returns a reference to the second exponent used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn dmq1(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut dq = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), &mut dq, ptr::null_mut());
            if dq.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(dq as *mut _))
            }
        }
    }

    /// Returns a reference to the coefficient used for CRT calculations.
    ///
    /// This corresponds to [`RSA_get0_crt_params`].
    ///
    /// [`RSA_get0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn iqmp(&self) -> Option<&BigNumRef> {
        unsafe {
            let mut qi = ptr::null();
            RSA_get0_crt_params(self.as_ptr(), ptr::null_mut(), ptr::null_mut(), &mut qi);
            if qi.is_null() {
                None
            } else {
                Some(BigNumRef::from_ptr(qi as *mut _))
            }
        }
    }

    /// Validates RSA parameters for correctness
    ///
    /// This corresponds to [`RSA_check_key`].
    ///
    /// [`RSA_check_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_check_key.html
    #[allow(clippy::unnecessary_cast)]
    pub fn check_key(&self) -> Result<bool, ErrorStack> {
        unsafe {
            let result = ffi::RSA_check_key(self.as_ptr()) as i32;
            if result == -1 {
                Err(ErrorStack::get())
            } else {
                Ok(result == 1)
            }
        }
    }
}

impl<T> RsaRef<T>
where
    T: HasPublic,
{
    to_pem! {
        /// Serializes the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSA_PUBKEY`].
        ///
        /// [`PEM_write_bio_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/pem.html
        public_key_to_pem,
        ffi::PEM_write_bio_RSA_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        ///
        /// This corresponds to [`i2d_RSA_PUBKEY`].
        ///
        /// [`i2d_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/i2d_RSA_PUBKEY.html
        public_key_to_der,
        ffi::i2d_RSA_PUBKEY
    }

    to_pem! {
        /// Serializes the public key into a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The output will have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_RSAPublicKey`].
        ///
        /// [`PEM_write_bio_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/pem.html
        public_key_to_pem_pkcs1,
        ffi::PEM_write_bio_RSAPublicKey
    }

    to_der! {
        /// Serializes the public key into a DER-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// This corresponds to [`i2d_RSAPublicKey`].
        ///
        /// [`i2d_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_RSAPublicKey.html
        public_key_to_der_pkcs1,
        ffi::i2d_RSAPublicKey
    }

    /// Returns the size of the modulus in bytes.
    ///
    /// This corresponds to [`RSA_size`].
    ///
    /// [`RSA_size`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_size.html
    #[allow(clippy::unnecessary_cast)]
    pub fn size(&self) -> u32 {
        unsafe { ffi::RSA_size(self.as_ptr()) as u32 }
    }

    /// Decrypts data using the public key, returning the number of decrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_decrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_decrypt(
                from.len(),
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Encrypts data using the public key, returning the number of encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if `to` is smaller than `self.size()`.
    pub fn public_encrypt(
        &self,
        from: &[u8],
        to: &mut [u8],
        padding: Padding,
    ) -> Result<usize, ErrorStack> {
        assert!(from.len() <= i32::MAX as usize);
        assert!(to.len() >= self.size() as usize);

        unsafe {
            let len = cvt_n(ffi::RSA_public_encrypt(
                from.len(),
                from.as_ptr(),
                to.as_mut_ptr(),
                self.as_ptr(),
                padding.0,
            ))?;
            Ok(len as usize)
        }
    }

    /// Returns a reference to the modulus of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn n(&self) -> &BigNumRef {
        unsafe {
            let mut n = ptr::null();
            RSA_get0_key(self.as_ptr(), &mut n, ptr::null_mut(), ptr::null_mut());
            BigNumRef::from_ptr(n as *mut _)
        }
    }

    /// Returns a reference to the public exponent of the key.
    ///
    /// This corresponds to [`RSA_get0_key`].
    ///
    /// [`RSA_get0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_get0_key.html
    pub fn e(&self) -> &BigNumRef {
        unsafe {
            let mut e = ptr::null();
            RSA_get0_key(self.as_ptr(), ptr::null_mut(), &mut e, ptr::null_mut());
            BigNumRef::from_ptr(e as *mut _)
        }
    }
}

impl Rsa<Public> {
    /// Creates a new RSA key with only public components.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_new.html
    /// [`RSA_set0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_key.html
    pub fn from_public_components(n: BigNum, e: BigNum) -> Result<Rsa<Public>, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), ptr::null_mut());
            mem::forget((n, e));
            Ok(Rsa::from_ptr(rsa))
        }
    }

    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing an RSA key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_read_bio_RSA_PUBKEY`].
        ///
        /// [`PEM_read_bio_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_RSA_PUBKEY.html
        public_key_from_pem,
        Rsa<Public>,
        ffi::PEM_read_bio_RSA_PUBKEY
    }

    from_pem! {
        /// Decodes a PEM-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// The input should have a header of `-----BEGIN RSA PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPublicKey`].
        ///
        /// [`PEM_read_bio_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_RSAPublicKey.html
        public_key_from_pem_pkcs1,
        Rsa<Public>,
        ffi::PEM_read_bio_RSAPublicKey
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing an RSA key.
        ///
        /// This corresponds to [`d2i_RSA_PUBKEY`].
        ///
        /// [`d2i_RSA_PUBKEY`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        public_key_from_der,
        Rsa<Public>,
        ffi::d2i_RSA_PUBKEY,
        ::libc::c_long
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPublicKey structure.
        ///
        /// This corresponds to [`d2i_RSAPublicKey`].
        ///
        /// [`d2i_RSAPublicKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        public_key_from_der_pkcs1,
        Rsa<Public>,
        ffi::d2i_RSAPublicKey,
        ::libc::c_long
    }
}

pub struct RsaPrivateKeyBuilder {
    rsa: Rsa<Private>,
}

impl RsaPrivateKeyBuilder {
    /// Creates a new `RsaPrivateKeyBuilder`.
    ///
    /// `n` is the modulus common to both public and private key.
    /// `e` is the public exponent and `d` is the private exponent.
    ///
    /// This corresponds to [`RSA_new`] and uses [`RSA_set0_key`].
    ///
    /// [`RSA_new`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_new.html
    /// [`RSA_set0_key`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_key.html
    pub fn new(n: BigNum, e: BigNum, d: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            let rsa = cvt_p(ffi::RSA_new())?;
            RSA_set0_key(rsa, n.as_ptr(), e.as_ptr(), d.as_ptr());
            mem::forget((n, e, d));
            Ok(RsaPrivateKeyBuilder {
                rsa: Rsa::from_ptr(rsa),
            })
        }
    }

    /// Sets the factors of the Rsa key.
    ///
    /// `p` and `q` are the first and second factors of `n`.
    ///
    /// This correspond to [`RSA_set0_factors`].
    ///
    /// [`RSA_set0_factors`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_factors.html
    // FIXME should be infallible
    pub fn set_factors(self, p: BigNum, q: BigNum) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_factors(self.rsa.as_ptr(), p.as_ptr(), q.as_ptr());
            mem::forget((p, q));
        }
        Ok(self)
    }

    /// Sets the Chinese Remainder Theorem params of the Rsa key.
    ///
    /// `dmp1`, `dmq1`, and `iqmp` are the exponents and coefficient for
    /// CRT calculations which is used to speed up RSA operations.
    ///
    /// This correspond to [`RSA_set0_crt_params`].
    ///
    /// [`RSA_set0_crt_params`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_set0_crt_params.html
    // FIXME should be infallible
    pub fn set_crt_params(
        self,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<RsaPrivateKeyBuilder, ErrorStack> {
        unsafe {
            RSA_set0_crt_params(
                self.rsa.as_ptr(),
                dmp1.as_ptr(),
                dmq1.as_ptr(),
                iqmp.as_ptr(),
            );
            mem::forget((dmp1, dmq1, iqmp));
        }
        Ok(self)
    }

    /// Returns the Rsa key.
    pub fn build(self) -> Rsa<Private> {
        self.rsa
    }
}

impl Rsa<Private> {
    /// Creates a new RSA key with private components (public components are assumed).
    ///
    /// This a convenience method over
    /// `Rsa::build(n, e, d)?.set_factors(p, q)?.set_crt_params(dmp1, dmq1, iqmp)?.build()`
    #[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
    pub fn from_private_components(
        n: BigNum,
        e: BigNum,
        d: BigNum,
        p: BigNum,
        q: BigNum,
        dmp1: BigNum,
        dmq1: BigNum,
        iqmp: BigNum,
    ) -> Result<Rsa<Private>, ErrorStack> {
        Ok(RsaPrivateKeyBuilder::new(n, e, d)?
            .set_factors(p, q)?
            .set_crt_params(dmp1, dmq1, iqmp)?
            .build())
    }

    /// Generates a public/private key pair with the specified size.
    ///
    /// The public exponent will be 65537.
    ///
    /// This corresponds to [`RSA_generate_key_ex`].
    ///
    /// [`RSA_generate_key_ex`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_generate_key_ex.html
    pub fn generate(bits: u32) -> Result<Rsa<Private>, ErrorStack> {
        let e = BigNum::from_u32(ffi::RSA_F4 as u32)?;
        Rsa::generate_with_e(bits, &e)
    }

    /// Generates a public/private key pair with the specified size and a custom exponent.
    ///
    /// Unless you have specific needs and know what you're doing, use `Rsa::generate` instead.
    ///
    /// This corresponds to [`RSA_generate_key_ex`].
    ///
    /// [`RSA_generate_key_ex`]: https://www.openssl.org/docs/man1.1.0/crypto/RSA_generate_key_ex.html
    pub fn generate_with_e(bits: u32, e: &BigNumRef) -> Result<Rsa<Private>, ErrorStack> {
        unsafe {
            let rsa = Rsa::from_ptr(cvt_p(ffi::RSA_new())?);
            cvt(ffi::RSA_generate_key_ex(
                rsa.0,
                bits as c_int,
                e.as_ptr(),
                ptr::null_mut(),
            ))?;
            Ok(rsa)
        }
    }

    // FIXME these need to identify input formats
    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted PKCS#1 RSAPrivateKey structure.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        ///
        /// This corresponds to [`PEM_read_bio_RSAPrivateKey`].
        ///
        /// [`PEM_read_bio_RSAPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_RSAPrivateKey.html
        private_key_from_pem_callback,
        Rsa<Private>,
        ffi::PEM_read_bio_RSAPrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded PKCS#1 RSAPrivateKey structure.
        ///
        /// This corresponds to [`d2i_RSAPrivateKey`].
        ///
        /// [`d2i_RSAPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_RSA_PUBKEY.html
        private_key_from_der,
        Rsa<Private>,
        ffi::d2i_RSAPrivateKey,
        ::libc::c_long
    }
}

impl<T> fmt::Debug for Rsa<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rsa")
    }
}

use crate::ffi::{
    RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_set0_crt_params, RSA_set0_factors,
    RSA_set0_key,
};

#[cfg(test)]
mod test {
    use crate::symm::Cipher;

    use super::*;

    #[test]
    fn test_from_password() {
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_passphrase(key, b"mypass").unwrap();
    }

    #[test]
    fn test_from_password_callback() {
        let mut password_queried = false;
        let key = include_bytes!("../test/rsa-encrypted.pem");
        Rsa::private_key_from_pem_callback(key, |password| {
            password_queried = true;
            password[..6].copy_from_slice(b"mypass");
            Ok(6)
        })
        .unwrap();

        assert!(password_queried);
    }

    #[test]
    fn test_to_password() {
        let key = Rsa::generate(2048).unwrap();
        let pem = key
            .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar")
            .unwrap();
        Rsa::private_key_from_pem_passphrase(&pem, b"foobar").unwrap();
        assert!(Rsa::private_key_from_pem_passphrase(&pem, b"fizzbuzz").is_err());
    }

    #[test]
    fn test_public_encrypt_private_decrypt_with_padding() {
        let key = include_bytes!("../test/rsa.pem.pub");
        let public_key = Rsa::public_key_from_pem(key).unwrap();

        let mut result = vec![0; public_key.size() as usize];
        let original_data = b"This is test";
        let len = public_key
            .public_encrypt(original_data, &mut result, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, 256);

        let pkey = include_bytes!("../test/rsa.pem");
        let private_key = Rsa::private_key_from_pem(pkey).unwrap();
        let mut dec_result = vec![0; private_key.size() as usize];
        let len = private_key
            .private_decrypt(&result, &mut dec_result, Padding::PKCS1)
            .unwrap();

        assert_eq!(&dec_result[..len], original_data);
    }

    #[test]
    fn test_private_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.public_key_to_pem().unwrap();
        let k1 = super::Rsa::public_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.private_encrypt(&msg, &mut emesg, Padding::PKCS1)
            .unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .public_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_encrypt() {
        let k0 = super::Rsa::generate(512).unwrap();
        let k0pkey = k0.private_key_to_pem().unwrap();
        let k1 = super::Rsa::private_key_from_pem(&k0pkey).unwrap();

        let msg = vec![0xdeu8, 0xadu8, 0xd0u8, 0x0du8];

        let mut emesg = vec![0; k0.size() as usize];
        k0.public_encrypt(&msg, &mut emesg, Padding::PKCS1).unwrap();
        let mut dmesg = vec![0; k1.size() as usize];
        let len = k1
            .private_decrypt(&emesg, &mut dmesg, Padding::PKCS1)
            .unwrap();
        assert_eq!(msg, &dmesg[..len]);
    }

    #[test]
    fn test_public_key_from_pem_pkcs1() {
        let key = include_bytes!("../test/pkcs1.pem.pub");
        Rsa::public_key_from_pem_pkcs1(key).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_public_key_from_pem_pkcs1_file_panic() {
        let key = include_bytes!("../test/key.pem.pub");
        Rsa::public_key_from_pem_pkcs1(key).unwrap();
    }

    #[test]
    fn test_public_key_to_pem_pkcs1() {
        let keypair = super::Rsa::generate(512).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_public_key_from_pem_pkcs1_generate_panic() {
        let keypair = super::Rsa::generate(512).unwrap();
        let pubkey_pem = keypair.public_key_to_pem().unwrap();
        super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
    }

    #[test]
    fn test_pem_pkcs1_encrypt() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = b"Hello, world!";

        let mut encrypted = vec![0; pubkey.size() as usize];
        let len = pubkey
            .public_encrypt(msg, &mut encrypted, Padding::PKCS1)
            .unwrap();
        assert!(len > msg.len());
        let mut decrypted = vec![0; keypair.size() as usize];
        let len = keypair
            .private_decrypt(&encrypted, &mut decrypted, Padding::PKCS1)
            .unwrap();
        assert_eq!(len, msg.len());
        assert_eq!(&decrypted[..len], msg);
    }

    #[test]
    fn test_pem_pkcs1_padding() {
        let keypair = super::Rsa::generate(2048).unwrap();
        let pubkey_pem = keypair.public_key_to_pem_pkcs1().unwrap();
        let pubkey = super::Rsa::public_key_from_pem_pkcs1(&pubkey_pem).unwrap();
        let msg = b"foo";

        let mut encrypted1 = vec![0; pubkey.size() as usize];
        let mut encrypted2 = vec![0; pubkey.size() as usize];
        let len1 = pubkey
            .public_encrypt(msg, &mut encrypted1, Padding::PKCS1)
            .unwrap();
        let len2 = pubkey
            .public_encrypt(msg, &mut encrypted2, Padding::PKCS1)
            .unwrap();
        assert!(len1 > (msg.len() + 1));
        assert_eq!(len1, len2);
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn clone() {
        let key = Rsa::generate(2048).unwrap();
        drop(key.clone());
    }

    #[test]
    fn generate_with_e() {
        let e = BigNum::from_u32(0x10001).unwrap();
        Rsa::generate_with_e(2048, &e).unwrap();
    }
}
