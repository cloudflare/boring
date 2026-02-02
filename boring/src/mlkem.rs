//! ML-KEM (FIPS 203) post-quantum key encapsulation.
//!
//! ML-KEM is a low-level cryptographic primitive. For most applications,
//! using higher-level constructions like HPKE is preferred.
//! Note that it's also enabled in TLS by default, in the X25519MLKEM768 exchange.
//!
//! Provides ML-KEM-768 (recommended) and ML-KEM-1024 variants via [`MlKem`].
//!
//! ```
//! use boring::mlkem::{MlKem, MlKemParams};
//!
//! let kem = MlKem::new(MlKemParams::MlKem768);
//! let (public_key, private_key) = kem.generate_key().unwrap();
//! let (ciphertext, shared_secret) = kem.encapsulate(&public_key).unwrap();
//! let decrypted = kem.decapsulate(&private_key, &ciphertext).unwrap();
//! assert_eq!(shared_secret, decrypted);
//! ```

use std::fmt;
use std::mem::MaybeUninit;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;

// CBS_init is inline in BoringSSL, so bindgen can't generate bindings for it.
#[inline]
fn cbs_init(data: &[u8]) -> ffi::CBS {
    ffi::CBS {
        data: data.as_ptr(),
        len: data.len(),
    }
}

/// Private key seed size (64 bytes).
pub const PRIVATE_KEY_SEED_BYTES: usize = ffi::MLKEM_SEED_BYTES as usize;

/// Shared secret size (32 bytes).
pub const SHARED_SECRET_BYTES: usize = ffi::MLKEM_SHARED_SECRET_BYTES as usize;

/// Raw bytes of the private key seed ([`PRIVATE_KEY_SEED_BYTES`] long)
pub type MlKemPrivateKeySeed = [u8; PRIVATE_KEY_SEED_BYTES];

/// Raw bytes of the shared secret ([`SHARED_SECRET_BYTES`] long)
pub type MlKemSharedSecret = [u8; SHARED_SECRET_BYTES];

/// ML-KEM variant selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemParams {
    /// Recommended. AES-192 equivalent security.
    MlKem768,
    /// AES-256 equivalent security.
    MlKem1024,
}

impl MlKemParams {
    /// Returns 1184 for ML-KEM-768, 1568 for ML-KEM-1024.
    #[must_use]
    pub const fn public_key_bytes(&self) -> usize {
        match self {
            MlKemParams::MlKem768 => MlKem768PublicKey::PUBLIC_KEY_BYTES,
            MlKemParams::MlKem1024 => MlKem1024PublicKey::PUBLIC_KEY_BYTES,
        }
    }

    /// Returns 1088 for ML-KEM-768, 1568 for ML-KEM-1024.
    #[must_use]
    pub const fn ciphertext_bytes(&self) -> usize {
        match self {
            MlKemParams::MlKem768 => MlKem768PrivateKey::CIPHERTEXT_BYTES,
            MlKemParams::MlKem1024 => MlKem1024PrivateKey::CIPHERTEXT_BYTES,
        }
    }
}

/// ML-KEM with runtime algorithm selection. Works with byte slices.
///
/// ```
/// use boring::mlkem::{MlKem, MlKemParams};
///
/// let kem = MlKem::new(MlKemParams::MlKem768);
/// let (public_key, private_key) = kem.generate_key().unwrap();
/// let (ciphertext, shared_secret) = kem.encapsulate(&public_key).unwrap();
/// let decrypted = kem.decapsulate(&private_key, &ciphertext).unwrap();
/// assert_eq!(shared_secret, decrypted);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct MlKem {
    params: MlKemParams,
}

impl MlKem {
    /// Creates a new context for the given parameter set.
    #[must_use]
    pub fn new(params: MlKemParams) -> Self {
        ffi::init();
        Self { params }
    }

    #[must_use]
    pub fn params(&self) -> MlKemParams {
        self.params
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> usize {
        self.params.public_key_bytes()
    }

    #[must_use]
    pub fn ciphertext_bytes(&self) -> usize {
        self.params.ciphertext_bytes()
    }

    /// Generates a new key pair, returning `(public_key, private_key)`.
    ///
    /// The private key is a 64-byte seed. Keep it secret.
    pub fn generate_key(&self) -> Result<(Vec<u8>, MlKemPrivateKeySeed), ErrorStack> {
        match self.params {
            MlKemParams::MlKem768 => {
                let (sk, pk) = MlKem768PrivateKey::generate();
                Ok((pk.bytes.to_vec(), sk.seed))
            }
            MlKemParams::MlKem1024 => {
                let (sk, pk) = MlKem1024PrivateKey::generate();
                Ok((pk.bytes.to_vec(), sk.seed))
            }
        }
    }

    /// Encapsulates a shared secret to the given public key, returning
    /// `(ciphertext, shared_secret)`.
    pub fn encapsulate(
        &self,
        public_key: &[u8],
    ) -> Result<(Vec<u8>, MlKemSharedSecret), ErrorStack> {
        match self.params {
            MlKemParams::MlKem768 => {
                let pk = MlKem768PublicKey::from_slice(public_key)?;
                let (ct, ss) = pk.encapsulate();
                Ok((ct.to_vec(), ss))
            }
            MlKemParams::MlKem1024 => {
                let pk = MlKem1024PublicKey::from_slice(public_key)?;
                let (ct, ss) = pk.encapsulate();
                Ok((ct.to_vec(), ss))
            }
        }
    }

    /// Decapsulates a shared secret from a ciphertext using the private key.
    pub fn decapsulate(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<MlKemSharedSecret, ErrorStack> {
        if private_key.len() != PRIVATE_KEY_SEED_BYTES {
            return Err(ErrorStack::internal_error_str("invalid private key length"));
        }
        let seed_arr: MlKemPrivateKeySeed = private_key.try_into().unwrap();

        match self.params {
            MlKemParams::MlKem768 => {
                let ct: &[u8; MlKem768PrivateKey::CIPHERTEXT_BYTES] = ciphertext
                    .try_into()
                    .map_err(|_| ErrorStack::internal_error_str("invalid ciphertext length"))?;
                let sk = MlKem768PrivateKey::from_seed(seed_arr)?;
                Ok(sk.decapsulate(ct))
            }
            MlKemParams::MlKem1024 => {
                let ct: &[u8; MlKem1024PrivateKey::CIPHERTEXT_BYTES] = ciphertext
                    .try_into()
                    .map_err(|_| ErrorStack::internal_error_str("invalid ciphertext length"))?;
                let sk = MlKem1024PrivateKey::from_seed(seed_arr)?;
                Ok(sk.decapsulate(ct))
            }
        }
    }
}

/// ML-KEM-768 private key.
///
/// Caches the expanded key for fast decapsulation.
struct MlKem768PrivateKey {
    seed: MlKemPrivateKeySeed,
    expanded: ffi::MLKEM768_private_key,
}

impl Clone for MlKem768PrivateKey {
    fn clone(&self) -> Self {
        // unwrap is safe: cloning a valid key with a valid seed always succeeds
        Self::from_seed(self.seed).unwrap()
    }
}

impl MlKem768PrivateKey {
    pub const CIPHERTEXT_BYTES: usize = ffi::MLKEM768_CIPHERTEXT_BYTES as usize;

    /// Generate a new key pair.
    #[must_use]
    fn generate() -> (MlKem768PrivateKey, MlKem768PublicKey) {
        // SAFETY: all buffers are out parameters, correctly sized
        unsafe {
            ffi::init();
            let mut public_key_bytes: MaybeUninit<[u8; MlKem768PublicKey::PUBLIC_KEY_BYTES]> =
                MaybeUninit::uninit();
            let mut seed: MaybeUninit<MlKemPrivateKeySeed> = MaybeUninit::uninit();
            let mut expanded: MaybeUninit<ffi::MLKEM768_private_key> = MaybeUninit::uninit();

            ffi::MLKEM768_generate_key(
                public_key_bytes.as_mut_ptr().cast(),
                seed.as_mut_ptr().cast(),
                expanded.as_mut_ptr(),
            );

            let bytes = public_key_bytes.assume_init();

            // Parse the public key bytes to get the parsed struct
            let mut cbs = cbs_init(&bytes);
            let mut parsed: MaybeUninit<ffi::MLKEM768_public_key> = MaybeUninit::uninit();
            ffi::MLKEM768_parse_public_key(parsed.as_mut_ptr(), &mut cbs);

            (
                MlKem768PrivateKey {
                    seed: seed.assume_init(),
                    expanded: expanded.assume_init(),
                },
                MlKem768PublicKey {
                    bytes,
                    parsed: parsed.assume_init(),
                },
            )
        }
    }

    /// Restore private key from seed.
    fn from_seed(seed: MlKemPrivateKeySeed) -> Result<Self, ErrorStack> {
        // SAFETY: seed is 64 bytes, out parameter correctly sized
        unsafe {
            ffi::init();
            let mut expanded: MaybeUninit<ffi::MLKEM768_private_key> = MaybeUninit::uninit();
            cvt(ffi::MLKEM768_private_key_from_seed(
                expanded.as_mut_ptr(),
                seed.as_ptr(),
                seed.len(),
            ))?;
            Ok(Self {
                seed,
                expanded: expanded.assume_init(),
            })
        }
    }

    /// Derive the public key.
    #[cfg(test)]
    fn public_key(&self) -> Result<MlKem768PublicKey, ErrorStack> {
        // SAFETY: expanded key is valid, buffers correctly sized
        unsafe {
            ffi::init();
            let mut parsed: MaybeUninit<ffi::MLKEM768_public_key> = MaybeUninit::uninit();
            ffi::MLKEM768_public_from_private(parsed.as_mut_ptr(), &self.expanded);

            let mut bytes = [0u8; MlKem768PublicKey::PUBLIC_KEY_BYTES];
            let mut cbb: MaybeUninit<ffi::CBB> = MaybeUninit::uninit();
            cvt(ffi::CBB_init_fixed(
                cbb.as_mut_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
            ))?;
            cvt(ffi::MLKEM768_marshal_public_key(
                cbb.as_mut_ptr(),
                parsed.as_ptr(),
            ))?;

            Ok(MlKem768PublicKey {
                bytes,
                parsed: parsed.assume_init(),
            })
        }
    }

    /// Decapsulate to get the shared secret.
    fn decapsulate(&self, ciphertext: &[u8; Self::CIPHERTEXT_BYTES]) -> MlKemSharedSecret {
        // SAFETY: expanded key is valid, ciphertext is correctly sized
        unsafe {
            ffi::init();
            let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

            ffi::MLKEM768_decap(
                shared_secret.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &self.expanded,
            );

            shared_secret
        }
    }
}

impl fmt::Debug for MlKem768PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768PrivateKey")
            .field("key", &"[redacted]")
            .finish()
    }
}

impl Drop for MlKem768PrivateKey {
    fn drop(&mut self) {
        // SAFETY: pointers and lengths are valid
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
            ffi::OPENSSL_cleanse(
                self.expanded.opaque.bytes.as_mut_ptr().cast(),
                self.expanded.opaque.bytes.len(),
            );
        }
    }
}

/// ML-KEM-768 public key.
#[derive(Clone)]
struct MlKem768PublicKey {
    bytes: [u8; Self::PUBLIC_KEY_BYTES],
    parsed: ffi::MLKEM768_public_key,
}

impl MlKem768PublicKey {
    pub const PUBLIC_KEY_BYTES: usize = ffi::MLKEM768_PUBLIC_KEY_BYTES as usize;

    /// Parse and validate a public key.
    ///
    /// The slice must be [`Self::PUBLIC_KEY_BYTES`] long.
    fn from_slice(slice: &[u8]) -> Result<Self, ErrorStack> {
        if slice.len() != Self::PUBLIC_KEY_BYTES {
            return Err(ErrorStack::internal_error_str("invalid public key length"));
        }

        // SAFETY: CBS correctly initialized, length already checked
        unsafe {
            ffi::init();
            let mut cbs = cbs_init(slice);
            let mut parsed: MaybeUninit<ffi::MLKEM768_public_key> = MaybeUninit::uninit();

            cvt(ffi::MLKEM768_parse_public_key(
                parsed.as_mut_ptr(),
                &mut cbs,
            ))?;
            if cbs.len != 0 {
                return Err(ErrorStack::internal_error_str(
                    "trailing bytes after public key",
                ));
            }

            let mut bytes = [0u8; Self::PUBLIC_KEY_BYTES];
            bytes.copy_from_slice(slice);
            Ok(Self {
                bytes,
                parsed: parsed.assume_init(),
            })
        }
    }

    /// Encapsulate: returns (ciphertext, shared_secret).
    fn encapsulate(
        &self,
    ) -> (
        [u8; MlKem768PrivateKey::CIPHERTEXT_BYTES],
        MlKemSharedSecret,
    ) {
        // SAFETY: buffers correctly sized, parsed key is valid
        unsafe {
            ffi::init();
            let mut ciphertext = [0u8; MlKem768PrivateKey::CIPHERTEXT_BYTES];
            let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

            ffi::MLKEM768_encap(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                &self.parsed,
            );

            (ciphertext, shared_secret)
        }
    }
}

impl fmt::Debug for MlKem768PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768PublicKey")
            .field("bytes", &format!("[{}]", self.bytes.len()))
            .finish()
    }
}

/// ML-KEM-1024 private key.
///
/// Prefer ML-KEM-768 unless you need AES-256 equivalent security.
/// Caches the expanded key for fast decapsulation.
struct MlKem1024PrivateKey {
    seed: MlKemPrivateKeySeed,
    expanded: ffi::MLKEM1024_private_key,
}

impl Clone for MlKem1024PrivateKey {
    fn clone(&self) -> Self {
        // unwrap is safe: cloning a valid key with a valid seed always succeeds
        Self::from_seed(self.seed).unwrap()
    }
}

impl MlKem1024PrivateKey {
    pub const CIPHERTEXT_BYTES: usize = ffi::MLKEM1024_CIPHERTEXT_BYTES as usize;

    /// Generate a new key pair.
    #[must_use]
    fn generate() -> (MlKem1024PrivateKey, MlKem1024PublicKey) {
        // SAFETY: all buffers are out parameters, correctly sized
        unsafe {
            ffi::init();
            let mut public_key_bytes: MaybeUninit<[u8; MlKem1024PublicKey::PUBLIC_KEY_BYTES]> =
                MaybeUninit::uninit();
            let mut seed: MaybeUninit<MlKemPrivateKeySeed> = MaybeUninit::uninit();
            let mut expanded: MaybeUninit<ffi::MLKEM1024_private_key> = MaybeUninit::uninit();

            ffi::MLKEM1024_generate_key(
                public_key_bytes.as_mut_ptr().cast(),
                seed.as_mut_ptr().cast(),
                expanded.as_mut_ptr(),
            );

            let bytes = public_key_bytes.assume_init();

            // Parse the public key bytes to get the parsed struct
            let mut cbs = cbs_init(&bytes);
            let mut parsed: MaybeUninit<ffi::MLKEM1024_public_key> = MaybeUninit::uninit();
            ffi::MLKEM1024_parse_public_key(parsed.as_mut_ptr(), &mut cbs);

            (
                MlKem1024PrivateKey {
                    seed: seed.assume_init(),
                    expanded: expanded.assume_init(),
                },
                MlKem1024PublicKey {
                    bytes,
                    parsed: parsed.assume_init(),
                },
            )
        }
    }

    /// Restore private key from seed.
    fn from_seed(seed: MlKemPrivateKeySeed) -> Result<Self, ErrorStack> {
        // SAFETY: seed is 64 bytes, out parameter correctly sized
        unsafe {
            ffi::init();
            let mut expanded: MaybeUninit<ffi::MLKEM1024_private_key> = MaybeUninit::uninit();
            cvt(ffi::MLKEM1024_private_key_from_seed(
                expanded.as_mut_ptr(),
                seed.as_ptr(),
                seed.len(),
            ))?;
            Ok(Self {
                seed,
                expanded: expanded.assume_init(),
            })
        }
    }

    /// Derive the public key.
    #[cfg(test)]
    fn public_key(&self) -> Result<MlKem1024PublicKey, ErrorStack> {
        // SAFETY: expanded key is valid, buffers correctly sized
        unsafe {
            ffi::init();
            let mut parsed: MaybeUninit<ffi::MLKEM1024_public_key> = MaybeUninit::uninit();
            ffi::MLKEM1024_public_from_private(parsed.as_mut_ptr(), &self.expanded);

            let mut bytes = [0u8; MlKem1024PublicKey::PUBLIC_KEY_BYTES];
            let mut cbb: MaybeUninit<ffi::CBB> = MaybeUninit::uninit();
            cvt(ffi::CBB_init_fixed(
                cbb.as_mut_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
            ))?;
            cvt(ffi::MLKEM1024_marshal_public_key(
                cbb.as_mut_ptr(),
                parsed.as_ptr(),
            ))?;

            Ok(MlKem1024PublicKey {
                bytes,
                parsed: parsed.assume_init(),
            })
        }
    }

    /// Decapsulate to get the shared secret.
    fn decapsulate(&self, ciphertext: &[u8; Self::CIPHERTEXT_BYTES]) -> MlKemSharedSecret {
        // SAFETY: expanded key is valid, ciphertext is correctly sized
        unsafe {
            ffi::init();
            let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

            ffi::MLKEM1024_decap(
                shared_secret.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &self.expanded,
            );

            shared_secret
        }
    }
}

impl fmt::Debug for MlKem1024PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem1024PrivateKey")
            .field("key", &"[redacted]")
            .finish()
    }
}

impl Drop for MlKem1024PrivateKey {
    fn drop(&mut self) {
        // SAFETY: pointers and lengths are valid
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
            ffi::OPENSSL_cleanse(
                self.expanded.opaque.bytes.as_mut_ptr().cast(),
                self.expanded.opaque.bytes.len(),
            );
        }
    }
}

/// ML-KEM-1024 public key.
///
/// Prefer ML-KEM-768 unless you need AES-256 equivalent security.
#[derive(Clone)]
struct MlKem1024PublicKey {
    bytes: [u8; Self::PUBLIC_KEY_BYTES],
    parsed: ffi::MLKEM1024_public_key,
}

impl MlKem1024PublicKey {
    pub const PUBLIC_KEY_BYTES: usize = ffi::MLKEM1024_PUBLIC_KEY_BYTES as usize;

    /// Parse and validate a serialized public key.
    ///
    /// The slice must be [`Self::PUBLIC_KEY_BYTES`] long.
    fn from_slice(slice: &[u8]) -> Result<Self, ErrorStack> {
        if slice.len() != Self::PUBLIC_KEY_BYTES {
            return Err(ErrorStack::internal_error_str("invalid public key length"));
        }

        // SAFETY: CBS correctly initialized, length already checked
        unsafe {
            ffi::init();
            let mut cbs = cbs_init(slice);
            let mut parsed: MaybeUninit<ffi::MLKEM1024_public_key> = MaybeUninit::uninit();

            cvt(ffi::MLKEM1024_parse_public_key(
                parsed.as_mut_ptr(),
                &mut cbs,
            ))?;
            if cbs.len != 0 {
                return Err(ErrorStack::internal_error_str(
                    "trailing bytes after public key",
                ));
            }

            let mut bytes = [0u8; Self::PUBLIC_KEY_BYTES];
            bytes.copy_from_slice(slice);
            Ok(Self {
                bytes,
                parsed: parsed.assume_init(),
            })
        }
    }

    /// Encapsulate: returns (ciphertext, shared_secret).
    fn encapsulate(
        &self,
    ) -> (
        [u8; MlKem1024PrivateKey::CIPHERTEXT_BYTES],
        [u8; SHARED_SECRET_BYTES],
    ) {
        // SAFETY: buffers correctly sized, parsed key is valid
        unsafe {
            ffi::init();
            let mut ciphertext = [0u8; MlKem1024PrivateKey::CIPHERTEXT_BYTES];
            let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

            ffi::MLKEM1024_encap(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                &self.parsed,
            );

            (ciphertext, shared_secret)
        }
    }
}

impl fmt::Debug for MlKem1024PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem1024PublicKey")
            .field("bytes", &format!("[{}]", self.bytes.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! mlkem_tests {
        ($name:ident, $priv:ty, $pub:ty, $ct_len:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn roundtrip() {
                    let (sk, pk) = <$priv>::generate();
                    let (ct, ss1) = pk.encapsulate();
                    let ss2 = sk.decapsulate(&ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn seed_roundtrip() {
                    let (sk, pk) = <$priv>::generate();
                    let sk2 = <$priv>::from_seed(sk.seed).unwrap();
                    let (ct, ss1) = pk.encapsulate();
                    let ss2 = sk2.decapsulate(&ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn derive_pubkey() {
                    let (sk, pk) = <$priv>::generate();
                    assert_eq!(pk.bytes, sk.public_key().unwrap().bytes);
                }

                #[test]
                fn from_slice_rejects_bad_len() {
                    assert!(<$pub>::from_slice(&[0u8; 100]).is_err());
                    assert!(<$pub>::from_slice(&[]).is_err());
                }

                #[test]
                fn from_slice_roundtrip() {
                    let (_, pk) = <$priv>::generate();
                    let pk2 = <$pub>::from_slice(&pk.bytes).unwrap();
                    assert_eq!(pk.bytes, pk2.bytes);
                }

                #[test]
                fn implicit_rejection() {
                    let (sk, _) = <$priv>::generate();
                    let bad_ct = [0x42u8; $ct_len];
                    // bad ciphertext still "works", just returns deterministic garbage
                    let ss1 = sk.decapsulate(&bad_ct);
                    let ss2 = sk.decapsulate(&bad_ct);
                    assert_eq!(ss1, ss2);
                }

                #[test]
                fn debug_redacts_seed() {
                    let (sk, _) = <$priv>::generate();
                    let dbg = format!("{:?}", sk);
                    assert!(dbg.contains("redacted"));
                }
            }
        };
    }

    mlkem_tests!(mlkem768, MlKem768PrivateKey, MlKem768PublicKey, 1088);
    mlkem_tests!(mlkem1024, MlKem1024PrivateKey, MlKem1024PublicKey, 1568);

    // Tests for unified API (MlKem struct)
    mod unified_api {
        use super::*;

        macro_rules! unified_tests {
            ($name:ident, $params:expr, $pk_len:expr, $ct_len:expr) => {
                mod $name {
                    use super::*;

                    #[test]
                    fn roundtrip() {
                        let kem = MlKem::new($params);
                        let (pk, seed) = kem.generate_key().unwrap();
                        let (ct, ss1) = kem.encapsulate(&pk).unwrap();
                        let ss2 = kem.decapsulate(&seed, &ct).unwrap();
                        assert_eq!(ss1, ss2);
                    }

                    #[test]
                    fn key_sizes() {
                        let kem = MlKem::new($params);
                        assert_eq!(kem.public_key_bytes(), $pk_len);
                        assert_eq!(kem.ciphertext_bytes(), $ct_len);

                        let (pk, private_key) = kem.generate_key().unwrap();
                        assert_eq!(pk.len(), $pk_len);
                        assert_eq!(private_key.len(), PRIVATE_KEY_SEED_BYTES);

                        let (ct, ss) = kem.encapsulate(&pk).unwrap();
                        assert_eq!(ct.len(), $ct_len);
                        assert_eq!(ss.len(), SHARED_SECRET_BYTES);
                    }

                    #[test]
                    fn invalid_public_key_length() {
                        let kem = MlKem::new($params);
                        let result = kem.encapsulate(&[0u8; 100]);
                        assert!(result.is_err());
                    }

                    #[test]
                    fn invalid_private_key_length() {
                        let kem = MlKem::new($params);
                        let (pk, _) = kem.generate_key().unwrap();
                        let (ct, _) = kem.encapsulate(&pk).unwrap();
                        let result = kem.decapsulate(&[0u8; 32], &ct);
                        assert!(result.is_err());
                    }

                    #[test]
                    fn invalid_ciphertext_length() {
                        let kem = MlKem::new($params);
                        let (_, private_key) = kem.generate_key().unwrap();
                        let result = kem.decapsulate(&private_key, &[0u8; 100]);
                        assert!(result.is_err());
                    }

                    #[test]
                    fn params_accessor() {
                        let kem = MlKem::new($params);
                        assert_eq!(kem.params(), $params);
                    }
                }
            };
        }

        unified_tests!(mlkem768, MlKemParams::MlKem768, 1184, 1088);
        unified_tests!(mlkem1024, MlKemParams::MlKem1024, 1568, 1568);

        #[test]
        fn params_constants() {
            assert_eq!(MlKemParams::MlKem768.public_key_bytes(), 1184);
            assert_eq!(MlKemParams::MlKem768.ciphertext_bytes(), 1088);
            assert_eq!(MlKemParams::MlKem1024.public_key_bytes(), 1568);
            assert_eq!(MlKemParams::MlKem1024.ciphertext_bytes(), 1568);
        }

        #[test]
        fn cross_kem_incompatibility() {
            // Keys from one KEM variant should not work with another
            let kem768 = MlKem::new(MlKemParams::MlKem768);
            let kem1024 = MlKem::new(MlKemParams::MlKem1024);

            let (pk768, _) = kem768.generate_key().unwrap();
            let (pk1024, _) = kem1024.generate_key().unwrap();

            // 768 public key is wrong length for 1024
            assert!(kem1024.encapsulate(&pk768).is_err());
            // 1024 public key is wrong length for 768
            assert!(kem768.encapsulate(&pk1024).is_err());
        }
    }
}
