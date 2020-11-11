use boring::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod};
use futures::future;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;
        let mut stream = tokio_boring::accept(&acceptor, stream).await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        let config = connector.build().configure().unwrap();

        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = tokio_boring::connect(config, "localhost", stream)
            .await
            .unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}
