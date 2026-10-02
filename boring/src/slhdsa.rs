use crate::cvt;
use crate::error::ErrorStack;
use std::fmt;

/// Supported SLH-DSA variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA2-128s
    Sha2128s,
    /// SHAKE-256f
    Shake256f,
}

impl Algorithm {
    /// Returns the encoded private key size in bytes.
    #[must_use]
    pub const fn private_key_bytes(&self) -> usize {
        match self {
            Self::Sha2128s => ffi::SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES as usize,
            Self::Shake256f => ffi::SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES as usize,
        }
    }

    /// Returns the encoded public key size in bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> usize {
        match self {
            Self::Sha2128s => ffi::SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES as usize,
            Self::Shake256f => ffi::SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES as usize,
        }
    }

    /// Returns the signature size in bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> usize {
        match self {
            Self::Sha2128s => ffi::SLHDSA_SHA2_128S_SIGNATURE_BYTES as usize,
            Self::Shake256f => ffi::SLHDSA_SHAKE_256F_SIGNATURE_BYTES as usize,
        }
    }
}

/// A SLH-DSA public key (any supported algorithm).
#[derive(Clone)]
pub struct SlhDsaPublicKey {
    algorithm: Algorithm,
    inner: PublicKeyInner,
}

#[derive(Clone)]
enum PublicKeyInner {
    Sha2128s([u8; ffi::SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES as usize]),
    Shake256f([u8; ffi::SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES as usize]),
}

/// An SLH-DSA private key (any supported algorithm).
#[derive(Clone)]
pub struct SlhDsaPrivateKey {
    algorithm: Algorithm,
    inner: PrivateKeyInner,
}

#[derive(Clone)]
enum PrivateKeyInner {
    Sha2128s([u8; ffi::SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES as usize]),
    Shake256f([u8; ffi::SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES as usize]),
}

impl SlhDsaPrivateKey {
    /// Generates a random SLH-DSA key pair.
    ///
    /// Returns `(public_key, private_key)`.
    pub fn generate(algorithm: Algorithm) -> (SlhDsaPublicKey, SlhDsaPrivateKey) {
        unsafe {
            ffi::init();
            match algorithm {
                Algorithm::Sha2128s => {
                    let mut pub_bytes = [0u8; ffi::SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES as usize];
                    let mut priv_bytes = [0u8; ffi::SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES as usize];
                    ffi::SLHDSA_SHA2_128S_generate_key(
                        pub_bytes.as_mut_ptr(),
                        priv_bytes.as_mut_ptr(),
                    );
                    (
                        SlhDsaPublicKey {
                            algorithm,
                            inner: PublicKeyInner::Sha2128s(pub_bytes),
                        },
                        SlhDsaPrivateKey {
                            algorithm,
                            inner: PrivateKeyInner::Sha2128s(priv_bytes),
                        },
                    )
                }
                Algorithm::Shake256f => {
                    let mut pub_bytes = [0u8; ffi::SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES as usize];
                    let mut priv_bytes = [0u8; ffi::SLHDSA_SHAKE_256F_PRIVATE_KEY_BYTES as usize];
                    ffi::SLHDSA_SHAKE_256F_generate_key(
                        pub_bytes.as_mut_ptr(),
                        priv_bytes.as_mut_ptr(),
                    );
                    (
                        SlhDsaPublicKey {
                            algorithm,
                            inner: PublicKeyInner::Shake256f(pub_bytes),
                        },
                        SlhDsaPrivateKey {
                            algorithm,
                            inner: PrivateKeyInner::Shake256f(priv_bytes),
                        },
                    )
                }
            }
        }
    }

    /// Import a serialized private key.
    pub fn from_slice(
        algorithm: Algorithm,
        serialized_private_key: &[u8],
    ) -> Result<Self, ErrorStack> {
        match algorithm {
            Algorithm::Sha2128s => {
                Ok(Self {
                    algorithm,
                    inner: PrivateKeyInner::Sha2128s(serialized_private_key.try_into().map_err(
                        |_| ErrorStack::internal_error_str("invalid private key length"),
                    )?),
                })
            }
            Algorithm::Shake256f => {
                Ok(Self {
                    algorithm,
                    inner: PrivateKeyInner::Shake256f(serialized_private_key.try_into().map_err(
                        |_| ErrorStack::internal_error_str("invalid private key length"),
                    )?),
                })
            }
        }
    }

    /// Returns the algorithm for this key.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the public key corresponding to this private key.
    pub fn public_key(&self) -> SlhDsaPublicKey {
        unsafe {
            ffi::init();
            match &self.inner {
                PrivateKeyInner::Sha2128s(key) => {
                    let mut pub_bytes = [0u8; ffi::SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES as usize];
                    ffi::SLHDSA_SHA2_128S_public_from_private(pub_bytes.as_mut_ptr(), key.as_ptr());
                    SlhDsaPublicKey {
                        algorithm: self.algorithm,
                        inner: PublicKeyInner::Sha2128s(pub_bytes),
                    }
                }
                PrivateKeyInner::Shake256f(key) => {
                    let mut pub_bytes = [0u8; ffi::SLHDSA_SHAKE_256F_PUBLIC_KEY_BYTES as usize];
                    ffi::SLHDSA_SHAKE_256F_public_from_private(
                        pub_bytes.as_mut_ptr(),
                        key.as_ptr(),
                    );
                    SlhDsaPublicKey {
                        algorithm: self.algorithm,
                        inner: PublicKeyInner::Shake256f(pub_bytes),
                    }
                }
            }
        }
    }

    /// Signs `msg` and returns the signature bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            ffi::init();
            match &self.inner {
                PrivateKeyInner::Sha2128s(key) => {
                    let mut sig = vec![0u8; ffi::SLHDSA_SHA2_128S_SIGNATURE_BYTES as usize];
                    cvt(ffi::SLHDSA_SHA2_128S_sign(
                        sig.as_mut_ptr(),
                        key.as_ptr(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                    Ok(sig)
                }
                PrivateKeyInner::Shake256f(key) => {
                    let mut sig = vec![0u8; ffi::SLHDSA_SHAKE_256F_SIGNATURE_BYTES as usize];
                    cvt(ffi::SLHDSA_SHAKE_256F_sign(
                        sig.as_mut_ptr(),
                        key.as_ptr(),
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

impl SlhDsaPublicKey {
    /// Parses a public key from its serialized form.
    pub fn from_slice(
        algorithm: Algorithm,
        serialized_public_key: &[u8],
    ) -> Result<Self, ErrorStack> {
        match algorithm {
            Algorithm::Sha2128s => {
                Ok(Self {
                    algorithm,
                    inner: PublicKeyInner::Sha2128s(serialized_public_key.try_into().map_err(
                        |_| ErrorStack::internal_error_str("invalid public key length"),
                    )?),
                })
            }
            Algorithm::Shake256f => {
                Ok(Self {
                    algorithm,
                    inner: PublicKeyInner::Shake256f(serialized_public_key.try_into().map_err(
                        |_| ErrorStack::internal_error_str("invalid public key length"),
                    )?),
                })
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
                PublicKeyInner::Sha2128s(key) => {
                    cvt(ffi::SLHDSA_SHA2_128S_verify(
                        signature.as_ptr(),
                        signature.len(),
                        key.as_ptr(),
                        msg.as_ptr(),
                        msg.len(),
                        core::ptr::null(),
                        0,
                    ))?;
                }
                PublicKeyInner::Shake256f(key) => {
                    cvt(ffi::SLHDSA_SHAKE_256F_verify(
                        signature.as_ptr(),
                        signature.len(),
                        key.as_ptr(),
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

impl fmt::Debug for SlhDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaPrivateKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl fmt::Debug for SlhDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaPublicKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl AsRef<[u8]> for SlhDsaPrivateKey {
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            PrivateKeyInner::Sha2128s(key) => key,
            PrivateKeyInner::Shake256f(key) => key,
        }
    }
}

impl AsRef<[u8]> for SlhDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        match &self.inner {
            PublicKeyInner::Sha2128s(key) => key,
            PublicKeyInner::Shake256f(key) => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! slhdsa_tests {
        ($name:ident, $alg:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn sign_and_verify() {
                    let (pk, sk) = SlhDsaPrivateKey::generate($alg);
                    let msg = b"test message";
                    let sig1 = sk.sign(msg).unwrap();
                    let sig2 = sk.clone().sign(msg).unwrap();
                    assert_eq!(sig1.len(), $alg.signature_bytes());
                    assert!(pk.verify(msg, &sig1).is_ok());
                    assert!(pk.verify(msg, &sig2).is_ok());
                    assert!(pk.clone().verify(msg, &sig1).is_ok());
                }

                #[test]
                fn bad_signature_fails() {
                    let (pk, sk) = SlhDsaPrivateKey::generate($alg);
                    let msg = b"test message";
                    let mut sig = sk.sign(msg).unwrap();
                    sig[5] ^= 1;
                    assert!(pk.verify(msg, &sig).is_err());
                }

                #[test]
                fn wrong_message_fails() {
                    let (pk, sk) = SlhDsaPrivateKey::generate($alg);
                    let sig = sk.sign(b"correct").unwrap();
                    assert!(pk.verify(b"wrong", &sig).is_err());
                }

                #[test]
                fn public_from_private() {
                    let (pk, sk) = SlhDsaPrivateKey::generate($alg);
                    let derived = sk.public_key();
                    assert_eq!(derived.algorithm(), $alg);
                    assert_eq!(derived.as_ref(), pk.as_ref());
                }
            }
        };
    }

    slhdsa_tests!(slhdsa_sha2_128s, Algorithm::Sha2128s);
    slhdsa_tests!(slhdsa_shake_256f, Algorithm::Shake256f);
}
