# Change Log

## [Unreleased]

## [v0.8.0] - 2019-12-10

### Changed

* Upgraded to hyper 0.13

## [v0.8.0-alpha.4] - 2019-09-04

### Changed

* Upgraded to hyper 0.13-alpha.4.

## [v0.8.0-alpha.1] - 2019-09-04

### Changed

* Upgraded to hyper 0.13-alpha.1.

## [v0.7.1] - 2019-03-01

### Changed

* TLSv1.3 sessions are now only used once, in accordance with the RFC's recommendation.

## [v0.7.0] - 2018-11-13

### Changed

* Upgraded `tokio-openssl` to 0.3. Handshake errors now return `openssl::ssl::HandshakeError`
    rather than `openssl::ssl::Error`.

## [v0.6.2] - 2018-11-07

### Added

* Added ALPN support. If the `h2` protocol is selected during the handshake via ALPN, the connector
    will automatically indicate that to Hyper via the `Connected::negotiated_h2` method. The
    `HttpsConnector::new` method configures ALPN to support both the `h2` and `http/1.1` protocols.
    Code using `HttpsConnector::with_connector` will need to configure ALPN manually.

## [v0.6.1] - 2018-06-13

### Changed

* `MaybeHttpsStream` now delegates `AsyncRead::read_buf` and `AsyncWrite::write_buf` to support
    readv/writev over HTTP connections.

## [v0.6.0] - 2018-06-04

### Changed

* Upgraded to hyper 0.12.
* The callback closure now takes a `&Destination` rather than a `&URI` to match what Hyper provides
    to connectors.

## [v0.5.0] - 2018-02-18

### Changed

* The `HttpsConnector::with_connector` function now takes an `SslConnectorBuilder` rather than an
    `SslConnector` due to a change in the session caching implementation. This is requried to
    properly support TLSv1.3.

## [v0.4.1] - 2018-01-11

### Changed

* Stopped enabling default features for `hyper`.

## [v0.4.0] - 2018-01-11

### Removed

* The `HttpsConnector::danger_disable_hostname_verification` method has been removed. Instead, use
    a callback which configures the `ConnectConfiguration` directly.

### Changed

* Upgraded to openssl 0.10.
* The `HttpsConnector::ssl_callback` method has been renamed to `HttpsConnector::set_callback`,
    and is passed a reference to the `ConnectConfiguration` rather than just the `SslRef`.

## Older

Look at the [release tags] for information about older releases.

[Unreleased]: https://github.com/sfackler/hyper-openssl/compare/0.8.0...master
[v0.8.0]: https://github.com/sfackler/hyper-openssl/compare/0.8.0-alpha.4...0.8.0
[v0.8.0-alpha.4]: https://github.com/sfackler/hyper-openssl/compare/0.8.0-alpha.1...0.8.0-alpha.4
[v0.8.0-alpha.1]: https://github.com/sfackler/hyper-openssl/compare/0.7.1...0.8.0-alpha.1
[v0.7.1]: https://github.com/sfackler/hyper-openssl/compare/0.7.0...0.7.1
[v0.7.0]: https://github.com/sfackler/hyper-openssl/compare/0.6.2...0.7.0
[v0.6.2]: https://github.com/sfackler/hyper-openssl/compare/0.6.1...0.6.2
[v0.6.1]: https://github.com/sfackler/hyper-openssl/compare/0.6.0...0.6.1
[v0.6.0]: https://github.com/sfackler/hyper-openssl/compare/0.5.0...0.6.0
[v0.5.0]: https://github.com/sfackler/hyper-openssl/compare/0.4.1...0.5.0
[v0.4.1]: https://github.com/sfackler/hyper-openssl/compare/0.4.0...0.4.1
[v0.4.0]: https://github.com/sfackler/hyper-openssl/compare/0.3.1...0.4.0
[release tags]: https://github.com/sfackler/hyper-openssl/releases
