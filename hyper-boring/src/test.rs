use std::{convert::Infallible, io, iter};

use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    body::{Body, Bytes},
    service, Response,
};
use hyper_util::{
    client::legacy::{
        connect::{Connect, HttpConnector},
        Client,
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::net::TcpListener;

use super::*;

#[tokio::test]
async fn google() {
    let ssl = HttpsConnector::new().unwrap();
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get("https://google.com".parse().unwrap())
            .await
            .expect("connection should succeed");
        resp.into_body().collect().await.unwrap();
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
            .set_private_key_file("test/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("test/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        for _ in 0..3 {
            let stream = listener.accept().await.unwrap().0;
            let stream = tokio_boring::accept(&acceptor, stream).await.unwrap();

            let service = service::service_fn(|_| async {
                Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
            });

            hyper::server::conn::http1::Builder::new()
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

    ssl.set_ca_file("test/root-ca.pem").unwrap();

    use std::fs::File;
    use std::io::Write;

    let file = File::create("../target/keyfile.log").unwrap();
    ssl.set_keylog_callback(move |_, line| {
        let _ = writeln!(&file, "{}", line);
    });

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get(format!("https://foobar.com:{}", port).parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        resp.into_body().collect().await.unwrap();
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
        // assert_eq!(stream.ssl().selected_alpn_protocol().unwrap(), b"h2");

        let service = service::service_fn(|_| async {
            Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
        });

        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
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

    ssl.set_ca_file("test/root-ca.pem").unwrap();
    ssl.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    let ssl = HttpsConnector::with_connector(connector, ssl).unwrap();
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    let resp = client
        .get(format!("https://foobar.com:{}", port).parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    resp.into_body().collect().await.unwrap();
}

fn pooling_client<C, B>(connector: C) -> Client<C, B>
where
    C: Connect + Clone,
    B: Body + Send,
    B::Data: Send,
{
    Client::builder(TokioExecutor::new())
        .timer(TokioTimer::new())
        .build(connector)
}
