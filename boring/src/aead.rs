//! High level interface to certain AEAD schemes.
//!
//! # Examples
//!
//! Encrypt data with AES128-GCM-SIV.
//!
//! ```
//! use boring::aead::{encrypt_aead, Aead};
//!
//! let aead = Aead::aes_128_gcm_siv();
//! let data = b"Some Crypto Text";
//! let aad = b"Some Crypto Context";
//! let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//! let nonce = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11";
//! let sealed_data = encrypt_aead(
//!     aead,
//!     key,
//!     nonce,
//!     aad,
//!     data).unwrap();
//!
//! assert_eq!(
//!     b"\x3D\xCC\xF8\x9A\x2B\xC1\x91\x15\xCD\x19\xD2\xC2\xB1\x13\x01\x38\xC5\
//!       \x7D\xF5\xEE\x5B\x37\xD1\x44\x05\xD2\x1A\xDA\x3F\x69\x97\x5D",
//!     &sealed_data[..]);
//! ```

use crate::ffi;
use libc::c_int;

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

use ffi::{
    EVP_AEAD_CTX_new, EVP_AEAD_key_length, EVP_AEAD_max_overhead, EVP_AEAD_max_tag_len,
    EVP_AEAD_nonce_length,
};

/// Represents a particular AEAD algorithm.
///
/// For more information see the BoringSSL documentation on [`aead.h`].
///
/// [`aead.h`]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Aead(*const ffi::EVP_AEAD);

impl Aead {
    pub fn aes_128_gcm() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_gcm()) }
    }

    pub fn aes_192_gcm() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_192_gcm()) }
    }

    pub fn aes_256_gcm() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_256_gcm()) }
    }

    pub fn chacha20_poly1305() -> Aead {
        unsafe { Aead(ffi::EVP_aead_chacha20_poly1305()) }
    }

    pub fn xchacha20_poly1305() -> Aead {
        unsafe { Aead(ffi::EVP_aead_xchacha20_poly1305()) }
    }

    pub fn aes_128_ctr_hmac_sha256() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_ctr_hmac_sha256()) }
    }

    pub fn aes_256_ctr_hmac_sha256() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_256_ctr_hmac_sha256()) }
    }

    pub fn aes_128_gcm_siv() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_gcm_siv()) }
    }

    pub fn aes_256_gcm_siv() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_256_gcm_siv()) }
    }

    /// Returns the length of keys used with this AEAD.
    pub fn key_len(&self) -> usize {
        unsafe { EVP_AEAD_key_length(self.0) as usize }
    }

    /// Returns the length of nonces used with this AEAD.
    pub fn nonce_len(&self) -> usize {
        unsafe { EVP_AEAD_nonce_length(self.0) as usize }
    }

    /// Returns the maximum ciphertext overhead with this AEAD.
    pub fn max_ciphertext_overhead(&self) -> usize {
        unsafe { EVP_AEAD_max_overhead(self.0) as usize }
    }

    /// Returns the maximum tag length with this AEAD.
    pub fn max_tag_length(&self) -> usize {
        unsafe { EVP_AEAD_max_tag_len(self.0) as usize }
    }

    pub fn as_ptr(&self) -> *const ffi::EVP_AEAD {
        self.0
    }
}

unsafe impl Sync for Aead {}
unsafe impl Send for Aead {}

/// Represents an AEAD context.
///
/// TODO: pick a better name!!
pub struct AeadCrypter {
    ctx: *mut ffi::EVP_AEAD_CTX,
    max_overhead: usize,
}

impl AeadCrypter {
    /// Creates a new `AeadCrypter`.
    pub fn new(aead: Aead, key: &[u8]) -> Result<AeadCrypter, ErrorStack> {
        ffi::init();

        unsafe {
            let ctx = cvt_p(EVP_AEAD_CTX_new(
                aead.as_ptr(),
                key.as_ptr(),
                key.len(),
                0, // supply tag_len = 0 so it picks the default one.
            ))?;
            let aeadcrypter = AeadCrypter {
                ctx,
                max_overhead: aead.max_ciphertext_overhead(),
            };
            Ok(aeadcrypter)
        }
    }

    /// Seals data by encrypting and authenticating the provided data and authenticating the provided aad.
    ///
    /// Returns the number of bytes written to output.
    ///
    /// # Panics
    ///
    /// Panics if `output.len() > c_int::max_value()`.
    ///
    /// Panics if `output.len() < data.len() + aead.max_overhead()`.
    pub fn seal(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() <= c_int::max_value() as usize);
            assert!(output.len() >= data.len() + self.max_overhead);

            let mut output_len = output.len();
            let nonce_len = nonce.len();
            let data_len = data.len();
            let aad_len = aad.len();

            cvt(ffi::EVP_AEAD_CTX_seal(
                self.ctx,
                output.as_mut_ptr(),
                &mut output_len,
                output_len,
                nonce.as_ptr(),
                nonce_len,
                data.as_ptr(),
                data_len,
                aad.as_ptr(),
                aad_len,
            ))?;

            Ok(output_len as usize)
        }
    }

    /// Opens data by authenticating the provided aad and authenticating and decrypting the provided data.
    ///
    /// Returns the number of bytes written to output.
    ///
    /// # Panics
    ///
    /// Panics if `output.len() > c_int::max_value()`.
    ///
    /// Panics if `output.len() < data.len()`.
    pub fn open(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ErrorStack> {
        unsafe {
            assert!(output.len() <= c_int::max_value() as usize);
            assert!(output.len() >= data.len());

            let mut output_len = output.len();
            let nonce_len = nonce.len();
            let data_len = data.len();
            let aad_len = aad.len();

            cvt(ffi::EVP_AEAD_CTX_open(
                self.ctx,
                output.as_mut_ptr(),
                &mut output_len,
                output_len,
                nonce.as_ptr(),
                nonce_len,
                data.as_ptr(),
                data_len,
                aad.as_ptr(),
                aad_len,
            ))?;

            Ok(output_len)
        }
    }
}

impl Drop for AeadCrypter {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_AEAD_CTX_free(self.ctx);
        }
    }
}

/// Encrypts the provided data and authenticates the ciphertext and the provided aad.
///
/// Returns the sealed data as a vector.
pub fn encrypt_aead(
    aead: Aead,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut aeadcrypter = AeadCrypter::new(aead, key)?;
    let mut output = vec![0u8; data.len() + aead.max_ciphertext_overhead()];
    let bytes_written_to_output = aeadcrypter.seal(nonce, aad, data, &mut output)?;
    Ok(output[..bytes_written_to_output].to_vec())
}

/// Authenticates the provided data and aad and decrypts the provided data.
///
/// Returns the unsealed data as a vector.
pub fn decrypt_aead(
    aead: Aead,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut aeadcrypter = AeadCrypter::new(aead, key)?;
    let mut output = vec![0u8; data.len()];
    let bytes_written_to_output = aeadcrypter.open(nonce, aad, data, &mut output)?;
    Ok(output[..bytes_written_to_output].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{self, FromHex};

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let aad = [0u8; 16];
        let data = [0u8; 16];

        let encrypted_data = encrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &data).unwrap();
        let decrypted_data =
            decrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &encrypted_data).unwrap();
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_aes_128_gcm_nist_test_vector() {
        // A NIST AES-GCM Test Vector from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS

        let key = Vec::from_hex("78e53ed07c0f162406ee17c54344e2ae").unwrap();
        let nonce = Vec::from_hex("6ed7b5bb11c6a939cd89ace4").unwrap();
        let aad = Vec::from_hex("64cc7dadca51bdcfa9fd03969c19b356fcea6b81").unwrap();
        let data = Vec::from_hex("85ca499a25cc7a85b22a8208f48f6316f6d06af9ef8589dca095d58e2a75ce9d41e9c4260327799f43de4939a9ca3b3fc66d26").unwrap();

        let tag = Vec::from_hex("64dd1120250dfca1efd3a3043f0a1c33").unwrap(); // Note: the original NIST test vector had a 13-byte tag (because of course it did), I added the last "0a1c33" to make it the expected 16 bytes.

        let expected_encrypted_data = Vec::from_hex("070a337a3d84f6a6feea1d941c8287c2705a4b3af3e47f90e51303b7d37b9b9d7f977c2759a74ac6545f38d4022b642a6758de").unwrap();

        let encrypted_data = encrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &data).unwrap();
        assert_eq!(encrypted_data, [expected_encrypted_data, tag].concat());

        let decrypted_data =
            decrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &encrypted_data).unwrap();
        assert_eq!(decrypted_data, data);
    }
}
