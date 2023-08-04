use boring::ssl::{SslConnector, SslMethod};
use futures::future;
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod common;

use self::common::{connect, create_server, with_trivial_client_server_exchange};

#[tokio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let config = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap();
    let mut stream = tokio_boring::connect(config, "google.com", stream)
        .await
        .unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[tokio::test]
async fn server() {
    with_trivial_client_server_exchange(|_| ()).await;
}

#[tokio::test]
async fn handshake_error() {
    let (stream, addr) = create_server(|_| ());

    let server = async {
        let err = stream.await.unwrap_err();

        assert!(err.into_source_stream().is_some());
    };

    let client = async {
        let err = connect(addr, |_| Ok(())).await.unwrap_err();

        assert!(err.into_source_stream().is_some());
    };

    future::join(server, client).await;
}
