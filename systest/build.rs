extern crate ctest;

use std::env;

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    let target = env::var("TARGET").unwrap();

    cfg.include("../openssl-sys/deps/boringssl/src/include");

    // Needed to get OpenSSL to correctly undef symbols that are already on
    // Windows like X509_NAME
    if target.contains("windows") {
        cfg.header("windows.h");

        // weird "different 'const' qualifiers" error on Windows, maybe a cl.exe
        // thing?
        if target.contains("msvc") {
            cfg.flag("/wd4090");
        }

        // https://github.com/sfackler/rust-openssl/issues/889
        cfg.define("WIN32_LEAN_AND_MEAN", None);
    }

    let mut cfgs = vec![];

    cfgs.push("ossl101");
    cfgs.push("ossl102");
    cfgs.push("ossl102f");
    cfgs.push("ossl102h");
    cfgs.push("ossl110");

    for c in cfgs {
        cfg.cfg(c, None);
    }

    cfg.header("openssl/dh.h")
        .header("openssl/ossl_typ.h")
        .header("openssl/stack.h")
        .header("openssl/x509.h")
        .header("openssl/bio.h")
        .header("openssl/x509v3.h")
        .header("openssl/safestack.h")
        .header("openssl/hmac.h")
        .header("openssl/ssl.h")
        .header("openssl/err.h")
        .header("openssl/rand.h")
        .header("openssl/pkcs12.h")
        .header("openssl/bn.h")
        .header("openssl/aes.h")
        .header("openssl/evp.h")
        .header("openssl/x509_vfy.h");

    #[allow(clippy::if_same_then_else)]
    cfg.type_name(|s, is_struct, _is_union| {
        // Add some `*` on some callback parameters to get function pointer to
        // typecheck in C, especially on MSVC.
        if s == "PasswordCallback" {
            "pem_password_cb*".to_string()
        } else if s == "bio_info_cb" {
            "bio_info_cb*".to_string()
        } else if s == "_STACK" {
            "struct stack_st".to_string()
        // This logic should really be cleaned up
        } else if is_struct
            && s != "point_conversion_form_t"
            && s.chars().next().unwrap().is_lowercase()
        {
            format!("struct {}", s)
        } else if s.starts_with("stack_st_") {
            format!("struct {}", s)
        } else {
            s.to_string()
        }
    });
    cfg.skip_type(|s| {
        // function pointers are declared without a `*` in openssl so their
        // sizeof is 1 which isn't what we want.
        s == "PasswordCallback"
            || s == "pem_password_cb"
            || s == "bio_info_cb"
            || s.starts_with("CRYPTO_EX_")
    });
    cfg.skip_struct(|s| {
        s == "ProbeResult" || s == "X509_OBJECT_data" // inline union
    });
    cfg.skip_fn(move |s| {
        s == "CRYPTO_memcmp" ||                 // uses volatile

        // Skip some functions with function pointers on windows, not entirely
        // sure how to get them to work out...
        (target.contains("windows") && {
            s.starts_with("PEM_read_bio_") ||
            (s.starts_with("PEM_write_bio_") && s.ends_with("PrivateKey")) ||
            s == "d2i_PKCS8PrivateKey_bio" ||
            s == "SSL_get_ex_new_index" ||
            s == "SSL_CTX_get_ex_new_index" ||
            s == "CRYPTO_get_ex_new_index"
        })
    });
    cfg.skip_field_type(|s, field| {
        (s == "EVP_PKEY" && field == "pkey") ||      // union
            (s == "GENERAL_NAME" && field == "d") || // union
            (s == "X509_OBJECT" && field == "data") // union
    });
    cfg.skip_signededness(|s| {
        s.ends_with("_cb")
            || s.ends_with("_CB")
            || s.ends_with("_cb_fn")
            || s.starts_with("CRYPTO_")
            || s == "PasswordCallback"
            || s.ends_with("_cb_func")
            || s.ends_with("_cb_ex")
    });
    cfg.field_name(|_s, field| {
        if field == "type_" {
            "type".to_string()
        } else {
            field.to_string()
        }
    });
    cfg.fn_cname(|rust, link_name| link_name.unwrap_or(rust).to_string());
    cfg.generate("../openssl-sys/src/lib.rs", "all.rs");
}
