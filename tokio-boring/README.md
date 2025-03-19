# rama-boring-tokio

An implementation of SSL streams for Tokio backed by BoringSSL in function of [Rama](https://github.com/plabayo/rama).

[Documentation](https://docs.rs/rama-boring-tokio)

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
rama-boring-tokio = "0.2.0"
```

Then, use either `accept` or `connect` as appropriate.

```rust
use rama_boring::ssl;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let (tcp_stream, _addr) = listener.accept().await?;

    let server = ssl::SslMethod::tls_server();
    let mut ssl_builder = rama_boring::ssl::SslAcceptor::mozilla_modern(server)?;
    ssl_builder.set_default_verify_paths()?;
    ssl_builder.set_verify(ssl::SslVerifyMode::PEER);
    let acceptor = ssl_builder.build();
    let _ssl_stream = rama_boring_tokio::accept(&acceptor, tcp_stream).await?;
    Ok(())
}
```

This library is an implementation of TLS streams using BoringSSL for
negotiating the connection. Each TLS stream implements the `Read` and
`Write` traits to interact and interoperate with the rest of the futures I/O
ecosystem. Client connections initiated from this crate verify hostnames
automatically and by default.

`rama-boring-tokio` exports this ability through [`accept`] and [`connect`]. `accept` should
be used by servers, and `connect` by clients. These augment the functionality provided by the
[`boring`] crate, on which this crate is built. Configuration of TLS parameters is still
primarily done through the [`boring`] crate.

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

The project is based on a [tokio-boring](https://github.com/cloudflare/boring)
which itself is based on a fork of [tokio-openssl](https://github.com/sfackler/tokio-openssl).
