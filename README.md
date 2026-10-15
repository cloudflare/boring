# boring

[![crates.io](https://img.shields.io/crates/v/boring.svg)](https://crates.io/crates/boring)

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate provides safe bindings for the Rust programming language and TLS adapters for [tokio](https://github.com/tokio-rs/tokio)
and [hyper](https://github.com/hyperium/hyper) built on top of it.

It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/boring/latest/boring/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

## Documentation
 - Boring API: <https://docs.rs/boring>
 - tokio TLS adapters: <https://docs.rs/tokio-boring>
 - hyper HTTPS connector: <https://docs.rs/hyper-boring>
 - FFI bindings: <https://docs.rs/boring-sys>

## crates.io releases

A release PR contains exactly one commit that changes the workspace version, with all four published crates resolving to that version. The PR is merged into `master` using the repository's rebase-and-merge strategy, and its post-rebase merge commit must remain reachable from `master` when the release is started.

The release workflow is run from `master` through **Actions → Publish to crates.io** with the merged PR number and expected version, without the `v` prefix. It verifies the PR, merge commit, and crate versions before creating the immutable tag and publishing `boring-sys`. Once the first crate succeeds, it creates or reuses a non-latest GitHub Release and publishes `boring`, `tokio-boring`, and `hyper-boring` in dependency order. The GitHub Release is updated after each crate succeeds with a link to its crates.io version.

The annotated `v<version>` tag is created before publication as the release's immutable anchor. A partially completed release remains a non-latest GitHub Release and can be rerun with the same inputs; already-published crates remain linked in the Release body. After all crates publish successfully, the GitHub Release becomes the latest release. Pushing a tag alone does not publish a release. The `crates-io` environment policy permits `master` and retains its required reviewers.

On a rerun, an existing non-yanked crate version is accepted only when its crates.io checksum matches the archive generated from the release commit. A checksum mismatch stops the release rather than associating an artifact from another source with this release.

Versions with a prerelease component, such as `5.4.0-rc.1`, are marked as GitHub prereleases and never become the repository's Latest release.

# Upgrading from `boring` v4

 * First update to boring 4.22 and ensure it builds without any deprecation warnings.
 * `pq-experimental` Cargo feature is no longer needed. Post-quantum crypto is enabled by default.
 * `fips-precompiled` Cargo feature has been merged into `fips`. Set `BORING_BSSL_FIPS_PATH` env var to use a precompiled library.
 * `fips-compat` Cargo feature has been renamed to `legacy-compat-deprecated` (4cb7e260a85b7)
 * `SslCurve` and `SslCurveNid` have been removed. Curve names are more stable and portable identifiers. Use `curve_name()` and `set_curves_list()`.
 * `Ssl::new_from_ref` -> `Ssl::new()`.
 * `X509Builder::append_extension2` -> `X509Builder::append_extension`.
 * `X509Store` is now cheaply cloneable, but immutable. `SslContextBuilder.cert_store_mut()` can't be used after `.set_cert_store()`. If you need `.cert_store_mut()`, either don't overwrite the default store, or use `.set_cert_store_builder()`.
 * `X509StoreBuilder::add_cert` takes a reference.
 * `hyper` 0.x support has been removed. Use `hyper` 1.x.

To support both v4 and v5, add `boring = ">=4.22,<6"` to `Cargo.toml`. If you need to auto-detect the version selected, add `boring-sys = ">=4.22,<6"` as a direct dependency, and in your `build.rs` check if `DEP_BORINGSSL_VERSION_MAJOR` env var is set to `5`. Versions older than 5.2.0 don't set it.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [rust-openssl](https://github.com/sfackler/rust-openssl).
