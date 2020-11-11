use libc::*;

#[allow(unused_imports)]
use *;

pub enum ASN1_INTEGER {}
pub enum ASN1_GENERALIZEDTIME {}
pub enum ASN1_STRING {}
pub enum ASN1_BIT_STRING {}
pub enum ASN1_TIME {}
pub enum ASN1_TYPE {}
pub enum ASN1_OBJECT {}
pub enum ASN1_OCTET_STRING {}

pub enum bio_st {} // FIXME remove

pub enum BIO {}

pub enum BIGNUM {}

pub enum BN_BLINDING {}
pub enum BN_MONT_CTX {}

pub enum BN_CTX {}
pub enum BN_GENCB {}

pub enum EVP_CIPHER {}

pub enum EVP_CIPHER_CTX {}
pub enum EVP_MD {}

pub enum EVP_MD_CTX {}

pub enum EVP_PKEY {}

pub enum PKCS8_PRIV_KEY_INFO {}

pub enum EVP_PKEY_ASN1_METHOD {}

pub enum EVP_PKEY_CTX {}

pub enum HMAC_CTX {}

pub enum DH {}

pub enum DH_METHOD {}

pub enum DSA {}

pub enum DSA_METHOD {}

pub enum RSA {}

pub enum RSA_METHOD {}

pub enum EC_KEY {}

pub enum X509 {}

pub enum X509_ALGOR {}

pub enum X509_NAME {}

pub enum X509_STORE {}

pub enum X509_STORE_CTX {}
pub enum X509_VERIFY_PARAM {}

#[repr(C)]
pub struct X509V3_CTX {
    flags: c_int,
    issuer_cert: *mut c_void,
    subject_cert: *mut c_void,
    subject_req: *mut c_void,
    crl: *mut c_void,
    db_meth: *mut c_void,
    db: *mut c_void,
    // I like the last comment line, it is copied from OpenSSL sources:
    // Maybe more here
}
pub enum CONF {}
pub enum OPENSSL_INIT_SETTINGS {}

pub enum SSL {}

pub enum SSL_CTX {}

pub enum ENGINE {}

pub enum COMP_METHOD {}

pub enum CRYPTO_EX_DATA {}

pub enum OCSP_RESPONSE {}
