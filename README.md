# boring

[![crates.io](https://img.shields.io/crates/v/boring.svg)](https://crates.io/crates/boring)

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate provides safe bindings for the Rust programming language and TLS adapters for [tokio](https://github.com/tokio-rs/tokio)
and [hyper](https://github.com/hyperium/hyper) built on top of it.

## Documentation
 - Boring API: <https://docs.rs/boring>
 - tokio TLS adapters: <https://docs.rs/tokio-boring>
 - hyper HTTPS connector: <https://docs.rs/hyper-boring>
 - FFI bindings: <https://docs.rs/boring-sys>

# Upgrading from `boring` v4

 * First update to boring 4.21 and ensure it builds without any deprecation warnings.
 * `pq-experimental` Cargo feature is no longer needed. Post-quantum crypto is enabled by default.
 * `fips-precompiled` Cargo feature has been merged into `fips`. Set `BORING_BSSL_FIPS_PATH` env var to use a precompiled library.
 * `fips-compat` Cargo feature has been renamed to `legacy-compat-deprecated` (4cb7e260a85b7)
 * `SslCurve` and `SslCurveNid` have been removed. Curve names are more stable and portable identifiers. Use `curve_name()` and `set_curves_list()`.
 * `Ssl::new_from_ref` -> `Ssl::new()`.
 * `X509Builder::append_extension2` -> `X509Builder::append_extension`.
 * `X509Store` is now cheaply cloneable, but immutable. `SslContextBuilder.cert_store_mut()` can't be used after `.set_cert_store()`. If you need `.cert_store_mut()`, either don't overwrite the default store, or use `.set_cert_store_builder()`.
 * `X509StoreBuilder::add_cert` takes a reference.
 * `hyper` 0.x support has been removed. Use `hyper` 1.x.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [rust-openssl](https://github.com/sfackler/rust-openssl).
