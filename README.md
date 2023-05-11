# boring

[![crates.io](https://img.shields.io/crates/v/boring.svg)](https://crates.io/crates/boring)

BoringSSL bindings for the Rust programming language and TLS adapters for [tokio](https://github.com/tokio-rs/tokio)
and [hyper](https://github.com/hyperium/hyper) built on top of it.

[Documentation](https://docs.rs/boring).

## Release Support

By default, the crate statically links with the latest BoringSSL master branch.

## Support for pre-built binaries

While this crate can build BoringSSL on its own, you may want to provide pre-built binaries instead.
To do so, specify the environment variable `BORING_BSSL_PATH` with the path to the binaries.

You can also provide specific headers by setting `BORING_BSSL_INCLUDE_PATH`.

_Notes_: The crate will look for headers in the `$BORING_BSSL_INCLUDE_PATH/openssl/` folder, make sure to place your headers there.

_Warning_: When providing a different version of BoringSSL make sure to use a compatible one, the crate relies on the presence of certain functions.

## Building with a FIPS-validated module

Only BoringCrypto module version 853ca1ea1168dff08011e5d42d94609cc0ca2e27, as certified with 
[certificate 4156](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4407.pdf)
is supported by this crate. Support is enabled by this crate's `fips` feature.

`boring-sys` comes with a test that FIPS is enabled/disabled depending on the feature flag. You can run it as follows:
```bash
$ cargo test --features fips fips::is_enabled
```

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [rust-openssl](https://github.com/sfackler/rust-openssl).
