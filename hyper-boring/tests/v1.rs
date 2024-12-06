#![cfg(feature = "hyper1")]

use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyStream, Empty};
use hyper1::{service, Response};
use hyper_boring::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::{io, iter};
use tokio::net::TcpListener;
use tower::ServiceExt;

#[tokio::test]
async fn google() {
    let ssl = HttpsConnector::new().unwrap();
    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build::<_, Empty<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get("https://www.google.com".parse().unwrap())
            .await
            .expect("connection should succeed");
        let mut body = BodyStream::new(resp.into_body());
        while body.next().await.transpose().unwrap().is_some() {}
    }
}

#[tokio::test]
async fn localhost() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_session_id_context(b"test").unwrap();
        acceptor
            .set_private_key_file("tests/test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/test/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        for _ in 0..3 {
            let stream = listener.accept().await.unwrap().0;
            let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();

            let service = service::service_fn(|_| async {
                Ok::<_, io::Error>(Response::new(<Empty<Bytes>>::new()))
            });

            hyper1::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        }
    };
    tokio::spawn(server);

    let resolver =
        tower::service_fn(move |_name| async move { Ok::<_, Infallible>(iter::once(addr)) });

    let mut connector = HttpConnector::new_with_resolver(resolver);

    connector.enforce_http(false);

    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();

    ssl.set_ca_file("tests/test/root-ca.pem").unwrap();

    use std::fs::File;
    use std::io::Write;

    let file = File::create("../target/keyfile.log").unwrap();
    ssl.set_keylog_callback(move |_, line| {
        let _ = writeln!(&file, "{}", line);
    });

    let ssl = HttpsConnector::with_connector(connector.map_response(TokioIo::new), ssl).unwrap();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get(format!("https://foobar.com:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let mut body = BodyStream::new(resp.into_body());
        while body.next().await.transpose().unwrap().is_some() {}
    }
}

#[tokio::test]
async fn alpn_h2() {
    use boring::ssl::{self, AlpnError};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
        acceptor
            .set_certificate_chain_file("tests/test/cert.pem")
            .unwrap();
        acceptor
            .set_private_key_file("tests/test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
        });
        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;
        let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();
        assert_eq!(stream.ssl().selected_alpn_protocol().unwrap(), b"h2");

        let service = service::service_fn(|_| async {
            Ok::<_, io::Error>(Response::new(<Empty<Bytes>>::new()))
        });

        hyper1::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    };
    tokio::spawn(server);

    let resolver =
        tower::service_fn(move |_name| async move { Ok::<_, Infallible>(iter::once(addr)) });

    let mut connector = HttpConnector::new_with_resolver(resolver);

    connector.enforce_http(false);

    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();

    ssl.set_ca_file("tests/test/root-ca.pem").unwrap();

    let mut ssl =
        HttpsConnector::with_connector(connector.map_response(TokioIo::new), ssl).unwrap();

    ssl.set_ssl_callback(|ssl, _| ssl.set_alpn_protos(b"\x02h2\x08http/1.1"));

    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(ssl);

    let resp = client
        .get(format!("https://foobar.com:{}", port).parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let mut body = BodyStream::new(resp.into_body());
    while body.next().await.transpose().unwrap().is_some() {}
}
