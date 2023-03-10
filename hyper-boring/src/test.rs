use super::*;
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes};
use hyper::rt::Sleep;
use hyper::{service, Response};
use hyper_util::client::connect::{Connect, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

#[tokio::test]
async fn google() {
    let ssl = HttpsConnector::new().unwrap();
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get("https://www.google.com".parse().unwrap())
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        resp.into_body().collect().await.unwrap();
    }
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

            let service = service::service_fn(|_| async {
                Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
            });

            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
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
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    for _ in 0..3 {
        let resp = client
            .get(format!("https://localhost:{}", port).parse().unwrap())
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

        let service = service::service_fn(|_| async {
            Ok::<_, io::Error>(Response::new(Empty::<Bytes>::new()))
        });

        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
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
    let client = pooling_client::<_, Full<Bytes>>(ssl);

    let resp = client
        .get(format!("https://localhost:{}", port).parse().unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    resp.into_body().collect().await.unwrap();
}

/// A Timer that uses the tokio runtime.
#[derive(Clone, Debug)]
pub struct TokioTimer;

impl hyper::rt::Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        let s = tokio::time::sleep(duration);
        let hs = TokioSleep { inner: Box::pin(s) };
        Box::pin(hs)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: Box::pin(tokio::time::sleep_until(deadline.into())),
        })
    }
}

struct TokioTimeout<T> {
    inner: Pin<Box<tokio::time::Timeout<T>>>,
}

impl<T> Future for TokioTimeout<T>
where
    T: Future,
{
    type Output = Result<T::Output, tokio::time::error::Elapsed>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(context)
    }
}

// Use TokioSleep to get tokio::time::Sleep to implement Unpin.
// see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
pub(crate) struct TokioSleep {
    pub(crate) inner: Pin<Box<tokio::time::Sleep>>,
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

// Use HasSleep to get tokio::time::Sleep to implement Unpin.
// see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html

impl Sleep for TokioSleep {}

pub fn pooling_client<C, B>(connector: C) -> Client<C, B>
where
    C: Connect + Clone,
    B: Body + Send,
    B::Data: Send,
{
    Client::builder(TokioExecutor::new())
        .timer(TokioTimer)
        .build(connector)
}
