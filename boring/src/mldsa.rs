//! ML-DSA (FIPS 204) post-quantum digital signature.
//!
//! ```
//! use boring::mldsa::{MlDsaPrivateKey, MlDsaPublicKey, Algorithm};
//!
//! // Generate a key pair.
//! let (public_key, private_key) = MlDsaPrivateKey::generate(Algorithm::MlDsa65).unwrap();
//!
//! // Sign a message.
//! let message = b"hello post-quantum world";
//! let signature = private_key.sign(message).unwrap();
//!
//! // Verify the signature.
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```

use std::fmt;
use std::mem::MaybeUninit;

use crate::cvt;
use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::cbs_init;

/// Seed size (32 bytes, shared across all ML-DSA parameter sets).
pub const SEED_BYTES: usize = ffi::MLDSA_SEED_BYTES as usize;

/// Raw bytes of a private key seed ([`SEED_BYTES`] long).
pub type MlDsaSeed = [u8; SEED_BYTES];

/// ML-DSA parameter set selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// NIST security level 2 (AES-128 equivalent).
    MlDsa44,
    /// NIST security level 3 (AES-192 equivalent).
    MlDsa65,
    /// NIST security level 5 (AES-256 equivalent).
    MlDsa87,
}

impl Algorithm {
    /// Returns the encoded public key size in bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> usize {
        match self {
            Self::MlDsa44 => ffi::MLDSA44_PUBLIC_KEY_BYTES as usize,
            Self::MlDsa65 => ffi::MLDSA65_PUBLIC_KEY_BYTES as usize,
            Self::MlDsa87 => ffi::MLDSA87_PUBLIC_KEY_BYTES as usize,
        }
    }

    /// Returns the signature size in bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> usize {
        match self {
            Self::MlDsa44 => ffi::MLDSA44_SIGNATURE_BYTES as usize,
            Self::MlDsa65 => ffi::MLDSA65_SIGNATURE_BYTES as usize,
            Self::MlDsa87 => ffi::MLDSA87_SIGNATURE_BYTES as usize,
        }
    }
}

/// An ML-DSA public key (any parameter set).
pub struct MlDsaPublicKey {
    algorithm: Algorithm,
    inner: PublicKeyInner,
}

enum PublicKeyInner {
    MlDsa44(Box<ffi::MLDSA44_public_key>),
    MlDsa65(Box<ffi::MLDSA65_public_key>),
    MlDsa87(Box<ffi::MLDSA87_public_key>),
}

/// An ML-DSA private key (any parameter set).
pub struct MlDsaPrivateKey {
    algorithm: Algorithm,
    seed: MlDsaSeed,
    inner: PrivateKeyInner,
}

enum PrivateKeyInner {
    MlDsa44(Box<ffi::MLDSA44_private_key>),
    MlDsa65(Box<ffi::MLDSA65_private_key>),
    MlDsa87(Box<ffi::MLDSA87_private_key>),
}

impl MlDsaPrivateKey {
    /// Generates a random ML-DSA key pair.
    ///
    /// Returns `(public_key, private_key)`.
    pub fn generate(algorithm: Algorithm) -> Result<(MlDsaPublicKey, MlDsaPrivateKey), ErrorStack> {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA44_PUBLIC_KEY_BYTES as usize];
                    let mut seed = [0u8; SEED_BYTES];
                    let mut priv_key: MaybeUninit<ffi::MLDSA44_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA44_generate_key(
                        pub_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        priv_key.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_bytes(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        MlDsaPrivateKey {
                            algorithm,
                            seed,
                            inner: PrivateKeyInner::MlDsa44(Box::new(priv_key.assume_init())),
                        },
                    ))
                }
                Algorithm::MlDsa65 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA65_PUBLIC_KEY_BYTES as usize];
                    let mut seed = [0u8; SEED_BYTES];
                    let mut priv_key: MaybeUninit<ffi::MLDSA65_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA65_generate_key(
                        pub_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        priv_key.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_bytes(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        MlDsaPrivateKey {
                            algorithm,
                            seed,
                            inner: PrivateKeyInner::MlDsa65(Box::new(priv_key.assume_init())),
                        },
                    ))
                }
                Algorithm::MlDsa87 => {
                    let mut pub_bytes = [0u8; ffi::MLDSA87_PUBLIC_KEY_BYTES as usize];
                    let mut seed = [0u8; SEED_BYTES];
                    let mut priv_key: MaybeUninit<ffi::MLDSA87_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA87_generate_key(
                        pub_bytes.as_mut_ptr(),
                        seed.as_mut_ptr(),
                        priv_key.as_mut_ptr(),
                    ))?;
                    let public_key = MlDsaPublicKey::from_bytes(algorithm, &pub_bytes)?;
                    Ok((
                        public_key,
                        MlDsaPrivateKey {
                            algorithm,
                            seed,
                            inner: PrivateKeyInner::MlDsa87(Box::new(priv_key.assume_init())),
                        },
                    ))
                }
            }
        }
    }

    /// Regenerates a private key from a seed value.
    pub fn from_seed(algorithm: Algorithm, seed: &MlDsaSeed) -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut priv_key: MaybeUninit<ffi::MLDSA44_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA44_private_key_from_seed(
                        priv_key.as_mut_ptr(),
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        seed: *seed,
                        inner: PrivateKeyInner::MlDsa44(Box::new(priv_key.assume_init())),
                    })
                }
                Algorithm::MlDsa65 => {
                    let mut priv_key: MaybeUninit<ffi::MLDSA65_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA65_private_key_from_seed(
                        priv_key.as_mut_ptr(),
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        seed: *seed,
                        inner: PrivateKeyInner::MlDsa65(Box::new(priv_key.assume_init())),
                    })
                }
                Algorithm::MlDsa87 => {
                    let mut priv_key: MaybeUninit<ffi::MLDSA87_private_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA87_private_key_from_seed(
                        priv_key.as_mut_ptr(),
                        seed.as_ptr(),
                        seed.len(),
                    ))?;
                    Ok(Self {
                        algorithm,
                        seed: *seed,
                        inner: PrivateKeyInner::MlDsa87(Box::new(priv_key.assume_init())),
                    })
                }
            }
        }
    }

    /// Returns the algorithm for this key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the seed bytes for this private key.
    pub fn seed(&self) -> &MlDsaSeed {
        &self.seed
    }

    /// Signs `msg` and returns the signature bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PrivateKeyInner::MlDsa44(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA44_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA44_sign(
                        sig.as_mut_ptr(),
                        key.as_ref(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
                PrivateKeyInner::MlDsa65(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA65_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA65_sign(
                        sig.as_mut_ptr(),
                        key.as_ref(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
                PrivateKeyInner::MlDsa87(key) => {
                    let mut sig = vec![0u8; ffi::MLDSA87_SIGNATURE_BYTES as usize];
                    cvt(ffi::MLDSA87_sign(
                        sig.as_mut_ptr(),
                        key.as_ref(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
            }
        }
    }
}

impl MlDsaPublicKey {
    /// Parses a public key from its serialized form.
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::MlDsa44 => {
                    let mut cbs = cbs_init(bytes);
                    let mut key: MaybeUninit<ffi::MLDSA44_public_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA44_parse_public_key(key.as_mut_ptr(), &mut cbs))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-44 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa44(Box::new(key.assume_init())),
                    })
                }
                Algorithm::MlDsa65 => {
                    let mut cbs = cbs_init(bytes);
                    let mut key: MaybeUninit<ffi::MLDSA65_public_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA65_parse_public_key(key.as_mut_ptr(), &mut cbs))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-65 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa65(Box::new(key.assume_init())),
                    })
                }
                Algorithm::MlDsa87 => {
                    let mut cbs = cbs_init(bytes);
                    let mut key: MaybeUninit<ffi::MLDSA87_public_key> = MaybeUninit::uninit();
                    cvt(ffi::MLDSA87_parse_public_key(key.as_mut_ptr(), &mut cbs))?;
                    if cbs.len != 0 {
                        return Err(ErrorStack::internal_error_str(
                            "trailing bytes after ML-DSA-87 public key",
                        ));
                    }
                    Ok(Self {
                        algorithm,
                        inner: PublicKeyInner::MlDsa87(Box::new(key.assume_init())),
                    })
                }
            }
        }
    }

    /// Returns the algorithm for this key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Verifies `signature` over `msg` using this public key.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PublicKeyInner::MlDsa44(key) => {
                    cvt(ffi::MLDSA44_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
                PublicKeyInner::MlDsa65(key) => {
                    cvt(ffi::MLDSA65_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
                PublicKeyInner::MlDsa87(key) => {
                    cvt(ffi::MLDSA87_verify(
                        key.as_ref(),
                        signature.as_ptr(),
                        signature.len(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
            }
            Ok(())
        }
    }
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPrivateKey")
            .field("algorithm", &self.algorithm)
            .field("seed", &"[redacted]")
            .finish()
    }
}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        unsafe {
            ffi::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
        }
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaPublicKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! mldsa_tests {
        ($name:ident, $alg:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn sign_and_verify() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let msg = b"test message";
                    let sig = sk.sign(msg).unwrap();
                    assert_eq!(sig.len(), $alg.signature_bytes());
                    assert!(pk.verify(msg, &sig).is_ok());
                }

                #[test]
                fn bad_signature_fails() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let msg = b"test message";
                    let mut sig = sk.sign(msg).unwrap();
                    sig[5] ^= 1;
                    assert!(pk.verify(msg, &sig).is_err());
                }

                #[test]
                fn wrong_message_fails() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let sig = sk.sign(b"correct").unwrap();
                    assert!(pk.verify(b"wrong", &sig).is_err());
                }

                #[test]
                fn seed_roundtrip() {
                    let (pk, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let sk2 = MlDsaPrivateKey::from_seed($alg, sk.seed()).unwrap();
                    let msg = b"seed roundtrip";
                    let sig = sk2.sign(msg).unwrap();
                    assert!(pk.verify(msg, &sig).is_ok());
                }

                #[test]
                fn debug_redacts_seed() {
                    let (_, sk) = MlDsaPrivateKey::generate($alg).unwrap();
                    let dbg = format!("{:?}", sk);
                    assert!(dbg.contains("redacted"));
                    assert!(!dbg.contains(&format!("{:?}", sk.seed())));
                }
            }
        };
    }

    mldsa_tests!(mldsa44, Algorithm::MlDsa44);
    mldsa_tests!(mldsa65, Algorithm::MlDsa65);
    mldsa_tests!(mldsa87, Algorithm::MlDsa87);
}
