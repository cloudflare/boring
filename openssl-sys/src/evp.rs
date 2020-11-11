use libc::*;
use *;

pub const EVP_MAX_MD_SIZE: c_uint = 64;

pub const EVP_PKEY_RSA: c_int = NID_rsaEncryption;
pub const EVP_PKEY_DSA: c_int = NID_dsa;
pub const EVP_PKEY_DH: c_int = NID_dhKeyAgreement;
pub const EVP_PKEY_EC: c_int = NID_X9_62_id_ecPublicKey;
pub const EVP_PKEY_X25519: c_int = NID_X25519;
pub const EVP_PKEY_ED25519: c_int = NID_ED25519;
pub const EVP_PKEY_X448: c_int = NID_X448;
pub const EVP_PKEY_ED448: c_int = NID_ED448;

pub const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
pub const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
pub const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

pub unsafe fn EVP_get_digestbynid(type_: c_int) -> *const EVP_MD {
    EVP_get_digestbyname(OBJ_nid2sn(type_))
}

extern "C" {
    pub fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    pub fn EVP_MD_type(md: *const EVP_MD) -> c_int;

    pub fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> c_uint;
    pub fn EVP_CIPHER_block_size(cipher: *const EVP_CIPHER) -> c_uint;
    pub fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> c_uint;
}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
            pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
        }
    } else {
        extern "C" {
            pub fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
            pub fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);
        }
    }
}

extern "C" {
    pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD, imple: *mut ENGINE)
        -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, n: size_t) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    pub fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD) -> c_int;
    pub fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    pub fn EVP_DigestFinalXOF(ctx: *mut EVP_MD_CTX, res: *mut u8, len: usize) -> c_int;

    pub fn EVP_BytesToKey(
        typ: *const EVP_CIPHER,
        md: *const EVP_MD,
        salt: *const u8,
        data: *const u8,
        datalen: size_t,
        count: c_uint,
        key: *mut u8,
        iv: *mut u8,
    ) -> c_int;

    pub fn EVP_CipherInit(
        ctx: *mut EVP_CIPHER_CTX,
        evp: *const EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
        mode: c_int,
    ) -> c_int;
    pub fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
        enc: c_int,
    ) -> c_int;
    pub fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        outbuf: *mut u8,
        outlen: *mut c_int,
        inbuf: *const u8,
        inlen: c_int,
    ) -> c_int;
    pub fn EVP_CipherFinal_ex(ctx: *mut EVP_CIPHER_CTX, res: *mut u8, len: *mut c_int) -> c_int;

    pub fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_DigestSignFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *mut c_uchar,
        siglen: *mut size_t,
    ) -> c_int;
    pub fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    pub fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
    pub fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    pub fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        outm: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> c_int;
}

extern "C" {
    pub fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        sigret: *mut c_uchar,
        siglen: *mut size_t,
        tbs: *const c_uchar,
        tbslen: size_t,
    ) -> c_int;

    pub fn EVP_DigestVerify(
        ctx: *mut EVP_MD_CTX,
        sigret: *const c_uchar,
        siglen: size_t,
        tbs: *const c_uchar,
        tbslen: size_t,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_DigestVerifyFinal(
        ctx: *mut EVP_MD_CTX,
        sigret: *const c_uchar,
        siglen: size_t,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    pub fn EVP_MD_CTX_copy_ex(dst: *mut EVP_MD_CTX, src: *const EVP_MD_CTX) -> c_int;
    pub fn EVP_CIPHER_CTX_set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_uint) -> c_int;
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, padding: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        type_: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;

    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha224() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_sha512() -> *const EVP_MD;
    pub fn EVP_des_ecb() -> *const EVP_CIPHER;
    pub fn EVP_des_ede3() -> *const EVP_CIPHER;
    pub fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    pub fn EVP_des_cbc() -> *const EVP_CIPHER;
    pub fn EVP_rc4() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ofb() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ofb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ofb() -> *const EVP_CIPHER;

    #[cfg(not(ossl110))]
    pub fn OPENSSL_add_all_algorithms_noconf();

    pub fn EVP_get_digestbyname(name: *const c_char) -> *const EVP_MD;
    pub fn EVP_get_cipherbyname(name: *const c_char) -> *const EVP_CIPHER;

    pub fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> c_int;
}
cfg_if! {
    if #[cfg(any(ossl110, libressl280))] {
        extern "C" {
            pub fn EVP_PKEY_bits(key: *const EVP_PKEY) -> c_int;
        }
    } else {
        extern "C" {
            pub fn EVP_PKEY_bits(key: *mut EVP_PKEY) -> c_int;
        }
    }
}
extern "C" {
    pub fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, typ: c_int, key: *mut c_void) -> c_int;

    pub fn EVP_PKEY_set1_RSA(k: *mut EVP_PKEY, r: *mut RSA) -> c_int;
    pub fn EVP_PKEY_get1_RSA(k: *const EVP_PKEY) -> *mut RSA;
    pub fn EVP_PKEY_get1_DSA(k: *const EVP_PKEY) -> *mut DSA;
    pub fn EVP_PKEY_get1_DH(k: *const EVP_PKEY) -> *mut DH;
    pub fn EVP_PKEY_get1_EC_KEY(k: *const EVP_PKEY) -> *mut EC_KEY;

    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    pub fn EVP_PKEY_free(k: *mut EVP_PKEY);
    #[cfg(any(ossl110, libressl270))]
    pub fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int;

    pub fn d2i_AutoPrivateKey(
        a: *mut *mut EVP_PKEY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut EVP_PKEY;

    pub fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    pub fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> c_int;

    pub fn PKCS5_PBKDF2_HMAC_SHA1(
        pass: *const c_char,
        passlen: size_t,
        salt: *const u8,
        saltlen: size_t,
        iter: c_uint,
        keylen: size_t,
        out: *mut u8,
    ) -> c_int;
    pub fn PKCS5_PBKDF2_HMAC(
        pass: *const c_char,
        passlen: size_t,
        salt: *const c_uchar,
        saltlen: size_t,
        iter: c_uint,
        digest: *const EVP_MD,
        keylen: size_t,
        out: *mut u8,
    ) -> c_int;

    #[cfg(ossl110)]
    pub fn EVP_PBE_scrypt(
        pass: *const c_char,
        passlen: size_t,
        salt: *const c_uchar,
        saltlen: size_t,
        N: u64,
        r: u64,
        p: u64,
        maxmem: size_t,
        key: *mut c_uchar,
        keylen: size_t,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_PKEY_CTX_new(k: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    pub fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_derive_set_peer(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut c_uchar, size: *mut size_t) -> c_int;

    pub fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, key: *mut *mut EVP_PKEY) -> c_int;

    pub fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        pout: *mut c_uchar,
        poutlen: *mut size_t,
        pin: *const c_uchar,
        pinlen: size_t,
    ) -> c_int;
    pub fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        pout: *mut c_uchar,
        poutlen: *mut size_t,
        pin: *const c_uchar,
        pinlen: size_t,
    ) -> c_int;
}

extern "C" {
    pub fn EVP_PKCS82PKEY(p8: *mut PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY;
}

extern "C" {
    pub fn EVP_PKEY_get_raw_public_key(
        pkey: *const EVP_PKEY,
        ppub: *mut c_uchar,
        len: *mut size_t,
    ) -> c_int;
    pub fn EVP_PKEY_new_raw_public_key(
        ttype: c_int,
        e: *mut ENGINE,
        key: *const c_uchar,
        keylen: size_t,
    ) -> *mut EVP_PKEY;
    pub fn EVP_PKEY_get_raw_private_key(
        pkey: *const EVP_PKEY,
        ppriv: *mut c_uchar,
        len: *mut size_t,
    ) -> c_int;
    pub fn EVP_PKEY_new_raw_private_key(
        ttype: c_int,
        e: *mut ENGINE,
        key: *const c_uchar,
        keylen: size_t,
    ) -> *mut EVP_PKEY;
}

extern "C" {
    pub fn EVP_EncodeBlock(dst: *mut c_uchar, src: *const c_uchar, src_len: size_t) -> size_t;
    pub fn EVP_DecodeBlock(dst: *mut c_uchar, src: *const c_uchar, src_len: size_t) -> c_int;
}
