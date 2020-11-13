# tokio-boring

An implementation of SSL streams for Tokio built on top of the BoringSSL.

[Documentation](https://docs.rs/tokio-boring)

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
tokio-boring = "1.0.0"
```

Next, add this to your crate:

```rust
use tokio_boring::{SslConnectorExt, SslAcceptorExt};
```

This crate provides two extension traits, `SslConnectorExt` and
`SslAcceptorExt`, which augment the functionality provided by the [`boring` crate](https://github.com/cloudflare/boring).
These extension traits provide the ability to connect a stream
asynchronously and accept a socket asynchronously. Configuration of BoringSSL
parameters is still done through the support in the [`boring` crate](https://github.com/cloudflare/boring).


# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Serde by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Accolades

The project is based on a fork of [tokio-openssl](https://github.com/sfackler/tokio-openssl).
