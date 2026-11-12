use crate::error::ErrorStack;
use crate::{cvt_0i, cvt_p, ffi};
/// Curve25519.
//
/// Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.
use foreign_types::ForeignType;

/// x25519.
//
/// x25519 is the Diffie-Hellman primitive built from curve25519. It is
/// sometimes referred to as “curve25519”, but “x25519” is a more precise name.
/// See http://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748.
pub const X25519_PRIVATE_KEY_LEN: usize = 32;
pub const X25519_PUBLIC_VALUE_LEN: usize = 32;
pub const X25519_SHARED_KEY_LEN: usize = 32;

/// x25519_keypair sets |out_public_value| and |out_private_key| to a freshly
/// generated, public–private key pair.
pub fn x25519_keypair(out_public_value: &mut [u8], out_private_key: &mut [u8]) {
    unsafe {
        ffi::init();
        ffi::X25519_keypair(out_public_value.as_mut_ptr(), out_private_key.as_mut_ptr())
    }
}

/// x25519 writes a shared key to |out_shared_key| that is calculated from the
/// given private key and the peer's public value. It returns one on success and
/// zero on error.
//
/// Don't use the shared key directly, rather use a KDF and also include the two
/// public values as inputs.
pub fn x25519(
    out_shared_key: &mut [u8],
    private_key: &[u8],
    peer_public_value: &[u8],
) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        cvt_0i(ffi::X25519(
            out_shared_key.as_mut_ptr(),
            private_key.as_ptr(),
            peer_public_value.as_ptr(),
        ))
        .map(|_| ())
    }
}

/// x25519_public_from_private calculates a Diffie-Hellman public value from the
/// given private key and writes it to |out_public_value|.
pub fn x25519_public_from_private(out_public_value: &mut [u8], private_key: &[u8]) {
    unsafe {
        ffi::init();
        ffi::X25519_public_from_private(out_public_value.as_mut_ptr(), private_key.as_ptr())
    }
}

/// Ed25519.
//
/// Ed25519 is a signature scheme using a twisted-Edwards curve that is
/// birationally equivalent to curve25519.
//
/// Note that, unlike RFC 8032's formulation, our private key representation
/// includes a public key suffix to make multiple key signing operations with the
/// same key more efficient. The RFC 8032 private key is referred to in this
/// implementation as the "seed" and is the first 32 bytes of our private key.
pub const ED25519_PRIVATE_KEY_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// ed25519_keypair sets |out_public_key| and |out_private_key| to a freshly
/// generated, public–private key pair.
pub fn ed25519_keypair(out_public_value: &mut [u8], out_private_key: &mut [u8]) {
    unsafe {
        ffi::init();
        ffi::ED25519_keypair(out_public_value.as_mut_ptr(), out_private_key.as_mut_ptr())
    }
}

/// ed25519_sign sets |out_sig| to be a signature of |message_len| bytes from
/// |message| using |private_key|. It returns one on success or zero on
/// allocation failure.
pub fn ed25519_sign(
    out_sig: &mut [u8],
    message: &[u8],
    private_key: &[u8],
) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        cvt_0i(ffi::ED25519_sign(
            out_sig.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            private_key.as_ptr(),
        ))
        .map(|_| ())
    }
}

/// ed25519_verify returns one iff |signature| is a valid signature, by
/// |public_key| of |message_len| bytes from |message|. It returns zero
/// otherwise.
pub fn ed25519_verify(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        cvt_0i(ffi::ED25519_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            public_key.as_ptr(),
        ))
        .map(|_| ())
    }
}

/// ed25519_keypair_from_seed calculates a public and private key from an
/// Ed25519 “seed”. Seed values are not exposed by this API (although they
/// happen to be the first 32 bytes of a private key) so this function is for
/// interoperating with systems that may store just a seed instead of a full
/// private key.
pub fn ed25519_keypair_from_seed(
    out_public_key: &mut [u8],
    out_private_key: &mut [u8],
    seed: &[u8],
) {
    unsafe {
        ffi::init();
        ffi::ED25519_keypair_from_seed(
            out_public_key.as_mut_ptr(),
            out_private_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    }
}

/// SPAKE2.
//
/// SPAKE2 is a password-authenticated key-exchange. It allows two parties,
/// who share a low-entropy secret (i.e. password), to agree on a shared key.
/// An attacker can only make one guess of the password per execution of the
/// protocol.
//
/// See https://tools.ietf.org/html/draft-irtf-cfrg-spake2-02.

/// Spake2Role enumerates the different “roles” in SPAKE2. The protocol
/// requires that the symmetry of the two parties be broken so one participant
/// must be “Alice” and the other be “Bob”.
pub enum Spake2Role {
    Alice,
    Bob,
}

pub const SPAKE2_MAX_MSG_SIZE: usize = 32;
pub const SPAKE2_MAX_KEY_SIZE: usize = 64;

foreign_type_and_impl_send_sync! {
    type CType = ffi::SPAKE2_CTX;
    fn drop = ffi::SPAKE2_CTX_free;

    /// A SPAKE2 Context
    pub struct Spake2Context;
}

impl Spake2Context {
    //// Returns a new `Spake2Context`.
    ///
    //// See OpenSSL documentation at [`SPAKE2_CTX_new`].
    pub fn new(
        role: Spake2Role,
        my_name: &str,
        their_name: &str,
    ) -> Result<Spake2Context, ErrorStack> {
        unsafe {
            ffi::init();
            let role = match role {
                Spake2Role::Alice => ffi::spake2_role_t::spake2_role_alice,
                Spake2Role::Bob => ffi::spake2_role_t::spake2_role_bob,
            };
            cvt_p(ffi::SPAKE2_CTX_new(
                role,
                my_name.as_ptr(),
                my_name.len(),
                their_name.as_ptr(),
                their_name.len(),
            ))
            .map(|p| Spake2Context::from_ptr(p))
        }
    }

    /// SPAKE2_generate_msg generates a SPAKE2 message given |password|, writes
    /// it to |out| and sets |*out_len| to the number of bytes written.
    //
    /// At most |max_out_len| bytes are written to |out| and, in order to ensure
    /// success, |max_out_len| should be at least |SPAKE2_MAX_MSG_SIZE| bytes.
    //
    /// This function can only be called once for a given |SPAKE2_CTX|.
    pub fn generate_message(
        &self,
        out: &mut [u8],
        max_out_len: usize,
        password: &[u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            ffi::init();
            cvt_0i(ffi::SPAKE2_generate_msg(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut out.len(),
                max_out_len,
                password.as_ptr(),
                password.len(),
            ))
            .map(|_| ())
        }
    }
    /// SPAKE2_process_msg completes the SPAKE2 exchange given the peer's message in
    /// |their_msg|, writes at most |max_out_key_len| bytes to |out_key| and sets
    /// |*out_key_len| to the number of bytes written.
    //
    /// The resulting keying material is suitable for:
    ///   a) Using directly in a key-confirmation step: i.e. each side could
    ///      transmit a hash of their role, a channel-binding value and the key
    ///      material to prove to the other side that they know the shared key.
    ///   b) Using as input keying material to HKDF to generate a variety of subkeys
    ///      for encryption etc.
    //
    /// If |max_out_key_key| is smaller than the amount of key material generated
    /// then the key is silently truncated. If you want to ensure that no truncation
    /// occurs then |max_out_key| should be at least |SPAKE2_MAX_KEY_SIZE|.
    //
    /// You must call |generate_msg| on a given |Spake2Context| before calling
    /// this function. On successful return, |Spake2Context| is complete and
    /// no more action is allowed except dropping it.
    pub fn process_message(
        &self,
        out_key: &mut [u8],
        max_out_key_len: usize,
        their_message: &mut [u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            ffi::init();
            cvt_0i(ffi::SPAKE2_process_msg(
                self.as_ptr(),
                out_key.as_mut_ptr(),
                &mut out_key.len(),
                max_out_key_len,
                their_message.as_ptr(),
                their_message.len(),
            ))
            .map(|_| ())
        }
    }
}
