use bio::{MemBio, MemBioSlice};
use error::ErrorStack;
use ffi;
use foreign_types::ForeignTypeRef;
use libc::c_int;
use pkey::{HasPrivate, PKeyRef};
use stack::StackRef;
use std::ptr;
use symm::Cipher;
use x509::store::X509StoreRef;
use x509::{X509Ref, X509};
use {cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::PKCS7;
    fn drop = ffi::PKCS7_free;

    /// A PKCS#7 structure.
    ///
    /// Contains signed and/or encrypted data.
    pub struct Pkcs7;

    /// Reference to `Pkcs7`
    pub struct Pkcs7Ref;
}

bitflags! {
    pub struct Pkcs7Flags: c_int {
        const TEXT = ffi::PKCS7_TEXT;
        const NOCERTS = ffi::PKCS7_NOCERTS;
        const NOSIGS = ffi::PKCS7_NOSIGS;
        const NOCHAIN = ffi::PKCS7_NOCHAIN;
        const NOINTERN = ffi::PKCS7_NOINTERN;
        const NOVERIFY = ffi::PKCS7_NOVERIFY;
        const DETACHED = ffi::PKCS7_DETACHED;
        const BINARY = ffi::PKCS7_BINARY;
        const NOATTR = ffi::PKCS7_NOATTR;
        const NOSMIMECAP = ffi::PKCS7_NOSMIMECAP;
        const STREAM = ffi::PKCS7_STREAM;
        #[cfg(not(any(ossl101, ossl102, libressl)))]
        const NO_DUAL_CONTENT = ffi::PKCS7_NO_DUAL_CONTENT;
    }
}

impl Pkcs7 {
    from_pem! {
        /// Deserializes a PEM-encoded PKCS#7 signature
        ///
        /// The input should have a header of `-----BEGIN PKCS7-----`.
        ///
        /// This corresponds to [`PEM_read_bio_PKCS7`].
        ///
        /// [`PEM_read_bio_PKCS7`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_PKCS7.html
        from_pem,
        Pkcs7,
        ffi::PEM_read_bio_PKCS7
    }

    from_der! {
        /// Deserializes a DER-encoded PKCS#7 signature
        ///
        /// This corresponds to [`d2i_PKCS7`].
        ///
        /// [`d2i_PKCS7`]: https://www.openssl.org/docs/man1.1.0/man3/d2i_PKCS7.html
        from_der,
        Pkcs7,
        ffi::d2i_PKCS7,
        ::libc::size_t
    }

    /// Creates and returns a PKCS#7 `signedData` structure.
    ///
    /// `signcert` is the certificate to sign with, `pkey` is the corresponding
    /// private key. `certs` is an optional additional set of certificates to
    /// include in the PKCS#7 structure (for example any intermediate CAs in the
    /// chain).
    ///
    /// This corresponds to [`PKCS7_sign`].
    ///
    /// [`PKCS7_sign`]: https://www.openssl.org/docs/man1.0.2/crypto/PKCS7_sign.html
    pub fn sign<PT>(
        signcert: &X509Ref,
        pkey: &PKeyRef<PT>,
        certs: &StackRef<X509>,
        input: &[u8],
        flags: Pkcs7Flags,
    ) -> Result<Pkcs7, ErrorStack>
    where
        PT: HasPrivate,
    {
        let input_bio = MemBioSlice::new(input)?;
        unsafe {
            cvt_p(ffi::PKCS7_sign(
                signcert.as_ptr(),
                pkey.as_ptr(),
                certs.as_ptr(),
                input_bio.as_ptr(),
                flags.bits,
            ))
            .map(Pkcs7)
        }
    }
}

impl Pkcs7Ref {
    to_pem! {
        /// Serializes the data into a PEM-encoded PKCS#7 structure.
        ///
        /// The output will have a header of `-----BEGIN PKCS7-----`.
        ///
        /// This corresponds to [`PEM_write_bio_PKCS7`].
        ///
        /// [`PEM_write_bio_PKCS7`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_PKCS7.html
        to_pem,
        ffi::PEM_write_bio_PKCS7
    }

    to_der! {
        /// Serializes the data into a DER-encoded PKCS#7 structure.
        ///
        /// This corresponds to [`i2d_PKCS7`].
        ///
        /// [`i2d_PKCS7`]: https://www.openssl.org/docs/man1.1.0/man3/i2d_PKCS7.html
        to_der,
        ffi::i2d_PKCS7
    }
}

#[cfg(test)]
mod tests {
    use pkcs7::{Pkcs7, Pkcs7Flags};
    use pkey::PKey;
    use stack::Stack;
    use symm::Cipher;
    use x509::store::X509StoreBuilder;
    use x509::X509;

    #[test]
    fn encrypt_decrypt_test() {
        let cert = include_bytes!("../test/certs.pem");
        let cert = X509::from_pem(cert).unwrap();
        let mut certs = Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let message: String = String::from("foo");
        let cypher = Cipher::des_ede3_cbc();
        let flags = Pkcs7Flags::STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();

        let pkcs7 =
            Pkcs7::encrypt(&certs, message.as_bytes(), cypher, flags).expect("should succeed");

        let encrypted = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");

        let (pkcs7_decoded, _) = Pkcs7::from_smime(encrypted.as_slice()).expect("should succeed");

        let decoded = pkcs7_decoded
            .decrypt(&pkey, &cert, Pkcs7Flags::empty())
            .expect("should succeed");

        assert_eq!(decoded, message.into_bytes());
    }

    #[test]
    fn sign_verify_test_detached() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message = "foo";
        let flags = Pkcs7Flags::STREAM | Pkcs7Flags::DETACHED;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");
        println!("{:?}", String::from_utf8(signed.clone()).unwrap());
        let (pkcs7_decoded, content) =
            Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

        let mut output = Vec::new();
        pkcs7_decoded
            .verify(
                &certs,
                &store,
                Some(message.as_bytes()),
                Some(&mut output),
                flags,
            )
            .expect("should succeed");

        assert_eq!(output, message.as_bytes());
        assert_eq!(content.expect("should be non-empty"), message.as_bytes());
    }

    #[test]
    fn sign_verify_test_normal() {
        let cert = include_bytes!("../test/cert.pem");
        let cert = X509::from_pem(cert).unwrap();
        let certs = Stack::new().unwrap();
        let message = "foo";
        let flags = Pkcs7Flags::STREAM;
        let pkey = include_bytes!("../test/key.pem");
        let pkey = PKey::private_key_from_pem(pkey).unwrap();
        let mut store_builder = X509StoreBuilder::new().expect("should succeed");

        let root_ca = include_bytes!("../test/root-ca.pem");
        let root_ca = X509::from_pem(root_ca).unwrap();
        store_builder.add_cert(root_ca).expect("should succeed");

        let store = store_builder.build();

        let pkcs7 =
            Pkcs7::sign(&cert, &pkey, &certs, message.as_bytes(), flags).expect("should succeed");

        let signed = pkcs7
            .to_smime(message.as_bytes(), flags)
            .expect("should succeed");

        let (pkcs7_decoded, content) =
            Pkcs7::from_smime(signed.as_slice()).expect("should succeed");

        let mut output = Vec::new();
        pkcs7_decoded
            .verify(&certs, &store, None, Some(&mut output), flags)
            .expect("should succeed");

        assert_eq!(output, message.as_bytes());
        assert!(content.is_none());
    }

    #[test]
    fn invalid_from_smime() {
        let input = String::from("Invalid SMIME Message");
        let result = Pkcs7::from_smime(input.as_bytes());

        assert_eq!(result.is_err(), true)
    }
}
