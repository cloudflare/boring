use super::*;
use boring::ssl::{
    SslAcceptor, SslCurve, SslFiletype, SslMethod, SslSignatureAlgorithm, SslVerifyMode,
};
use futures::StreamExt;
use hyper::client::HttpConnector;
use hyper::server::conn::Http;
use hyper::{service, Response};
use hyper::{Body, Client};
use tokio::net::TcpListener;

#[tokio::test]
#[cfg(feature = "runtime")]
async fn google() {
    let ssl = HttpsConnector::new().unwrap();
    let client = Client::builder()
        .pool_max_idle_per_host(0)
        .build::<_, Body>(ssl);

    for _ in 0..3 {
        let resp = client
            .get("https://www.google.com".parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let mut body = resp.into_body();
        while body.next().await.transpose().unwrap().is_some() {}
    }
}

#[tokio::test]
#[cfg(feature = "runtime")]
async fn tls_fingerprint() {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES").unwrap();
    ssl.set_verify(SslVerifyMode::NONE);
    ssl.set_grease_enabled(true);
    ssl.add_cert_compression_alg(boring::ssl::CertCompressionAlgorithm::Brotli)
        .unwrap();
    ssl.enable_signed_cert_timestamps();
    ssl.enable_ocsp_stapling();
    ssl.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ])
    .unwrap();
    ssl.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])
        .unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    let resp = client
        .get("https://client.tlsfingerprint.io:8443/".parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let mut body: Body = resp.into_body();

    let value = body.next().await.unwrap().unwrap();
    dbg!(String::from_utf8(value.to_vec()).unwrap());
}

#[tokio::test]
async fn localhost() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_session_id_context(b"test").unwrap();
        acceptor
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        for _ in 0..3 {
            let stream = listener.accept().await.unwrap().0;
            let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();

            let service =
                service::service_fn(|_| async { Ok::<_, io::Error>(Response::new(Body::empty())) });

            Http::new()
                .http1_keep_alive(false)
                .serve_connection(stream, service)
                .await
                .unwrap();
        }
    };
    tokio::spawn(server);

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();

    use std::fs::File;
    use std::io::Write;

    let file = File::create("../target/keyfile.log").unwrap();
    ssl.set_keylog_callback(move |_, line| {
        let _ = writeln!(&file, "{}", line);
    });

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    for _ in 0..3 {
        let resp = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let mut body = resp.into_body();
        while body.next().await.transpose().unwrap().is_some() {}
    }
}

#[tokio::test]
async fn alpn_h2() {
    use boring::ssl::{self, AlpnError};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        acceptor
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
        });
        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;
        let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();
        assert_eq!(stream.ssl().selected_alpn_protocol().unwrap(), b"h2");

        let service =
            service::service_fn(|_| async { Ok::<_, io::Error>(Response::new(Body::empty())) });

        Http::new()
            .http2_only(true)
            .serve_connection(stream, service)
            .await
            .unwrap();
    };
    tokio::spawn(server);

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    ssl.set_ca_file("test/cert.pem").unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = Client::builder().build::<_, Body>(ssl);

    let resp = client
        .get(format!("https://localhost:{}", port).parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let mut body = resp.into_body();
    while body.next().await.transpose().unwrap().is_some() {}
}
