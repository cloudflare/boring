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

    #[cfg(feature = "fips")]
    pub fn aes_128_gcm_randnonce() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_gcm_randnonce()) }
    }

    #[cfg(feature = "fips")]
    pub fn aes_256_gcm_randnonce() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_256_gcm_randnonce()) }
    }

    pub fn aes_128_ccm_bluetooth() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_ccm_bluetooth()) }
    }

    pub fn aes_128_ccm_bluetooth_8() -> Aead {
        unsafe { Aead(ffi::EVP_aead_aes_128_ccm_bluetooth_8()) }
    }

    /// Returns the length of keys used with this AEAD.
    pub fn key_len(&self) -> usize {
        unsafe { EVP_AEAD_key_length(self.0) as usize }
    }

    /// Returns the length of nonces used with this AEAD.
    pub fn nonce_len(&self) -> usize {
        unsafe { EVP_AEAD_nonce_length(self.0) as usize }
    }

    /// Returns the maximum number of additional bytes added by the act of sealing data with `self`.
    ///
    /// Corresponds to [`EVP_AEAD_max_overhead`](https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_max_overhead).
    pub fn max_overhead(&self) -> usize {
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

/// Represents an AEAD context.
pub struct AeadContext {
    ctx: *mut ffi::EVP_AEAD_CTX,
    max_overhead: usize,
}

impl AeadContext {
    /// Creates a new `AeadContext`.
    pub fn new(aead: Aead, key: &[u8]) -> Result<AeadContext, ErrorStack> {
        ffi::init();

        unsafe {
            let ctx = cvt_p(EVP_AEAD_CTX_new(
                aead.as_ptr(),
                key.as_ptr(),
                key.len(),
                0, // supply tag_len = 0 so it picks the default one.
            ))?;
            let aeadcontext = AeadContext {
                ctx,
                max_overhead: aead.max_overhead(),
            };
            Ok(aeadcontext)
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

impl Drop for AeadContext {
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
    let mut aeadcontext = AeadContext::new(aead, key)?;
    let mut output = vec![0u8; data.len() + aead.max_overhead()];
    let bytes_written_to_output = aeadcontext.seal(nonce, aad, data, &mut output)?;
    output.truncate(bytes_written_to_output);
    Ok(output)
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
    let mut aeadcontext = AeadContext::new(aead, key)?;
    let mut output = vec![0u8; data.len()];
    let bytes_written_to_output = aeadcontext.open(nonce, aad, data, &mut output)?;
    Ok(output[..bytes_written_to_output].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{self, FromHex};

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [42u8; 16];
        let nonce = [42u8; 16];
        let aad = [42u8; 16];
        let data = [42u8; 16];

        let encrypted_data = encrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &data).unwrap();
        let decrypted_data =
            decrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &encrypted_data).unwrap();
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_xchacha20_poly1305_rfc_test_vector() {
        // Test Vector from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.1
        let key = Vec::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = Vec::from_hex("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let aad = Vec::from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let data = Vec::from_hex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();

        let expected_tag = Vec::from_hex("c0875924c1c7987947deafd8780acf49").unwrap();
        let expected_encrypted_data = Vec::from_hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e").unwrap();

        let encrypted_data =
            encrypt_aead(Aead::xchacha20_poly1305(), &key, &nonce, &aad, &data).unwrap();
        assert_eq!(
            encrypted_data,
            [expected_encrypted_data, expected_tag].concat()
        );

        let decrypted_data = decrypt_aead(
            Aead::xchacha20_poly1305(),
            &key,
            &nonce,
            &aad,
            &encrypted_data,
        )
        .unwrap();
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_aes_128_gcm_siv_rfc_test_vector() {
        // Test Vector from https://datatracker.ietf.org/doc/html/rfc8452#appendix-C.1
        let key = Vec::from_hex("f901cfe8a69615a93fdf7a98cad48179").unwrap();
        let nonce = Vec::from_hex("6245709fb18853f68d833640").unwrap();
        let aad =
            Vec::from_hex("7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21")
                .unwrap();
        let data = Vec::from_hex("e42a3c02c25b64869e146d7b233987bddfc240871d").unwrap();

        let expected_encrypted_data = Vec::from_hex(
            "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70",
        )
        .unwrap();

        let encrypted_data =
            encrypt_aead(Aead::aes_128_gcm_siv(), &key, &nonce, &aad, &data).unwrap();
        assert_eq!(encrypted_data, expected_encrypted_data);

        let decrypted_data =
            decrypt_aead(Aead::aes_128_gcm_siv(), &key, &nonce, &aad, &encrypted_data).unwrap();
        assert_eq!(decrypted_data, data);
    }

    #[test]
    fn test_aes_256_gcm_nist_test_vector() {
        // A NIST AES-GCM Test Vector from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS

        let key = Vec::from_hex("78e53ed07c0f162406ee17c54344e2ae").unwrap();
        let nonce = Vec::from_hex("6ed7b5bb11c6a939cd89ace4").unwrap();
        let aad = Vec::from_hex("64cc7dadca51bdcfa9fd03969c19b356fcea6b81").unwrap();
        let data = Vec::from_hex("85ca499a25cc7a85b22a8208f48f6316f6d06af9ef8589dca095d58e2a75ce9d41e9c4260327799f43de4939a9ca3b3fc66d26").unwrap();

        let expected_tag = Vec::from_hex("64dd1120250dfca1efd3a3043f0a1c33").unwrap(); // Note: the original NIST test vector had a 13-byte tag (because of course it did), I added the last "0a1c33" to make it the expected 16 bytes.
        let expected_encrypted_data = Vec::from_hex("070a337a3d84f6a6feea1d941c8287c2705a4b3af3e47f90e51303b7d37b9b9d7f977c2759a74ac6545f38d4022b642a6758de").unwrap();

        let encrypted_data = encrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &data).unwrap();
        assert_eq!(
            encrypted_data,
            [expected_encrypted_data, expected_tag].concat()
        );

        let decrypted_data =
            decrypt_aead(Aead::aes_128_gcm(), &key, &nonce, &aad, &encrypted_data).unwrap();
        assert_eq!(decrypted_data, data);
    }
}
