#![allow(dead_code)]

use boring::error::ErrorStack;
use boring::ssl::{
    SslAcceptor, SslAcceptorBuilder, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod,
};
use futures::future::{self, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_boring::{HandshakeError, SslStream};

pub(crate) fn create_server(
    setup: impl FnOnce(&mut SslAcceptorBuilder),
) -> (
    impl Future<Output = Result<SslStream<TcpStream>, HandshakeError<TcpStream>>>,
    SocketAddr,
) {
    let (listener, addr) = create_listener();

    let server = async move {
        let acceptor = create_acceptor(setup);

        let stream = listener.accept().await.unwrap().0;

        tokio_boring::accept(&acceptor, stream).await
    };

    (server, addr)
}

pub(crate) fn create_listener() -> (TcpListener, SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

    listener.set_nonblocking(true).unwrap();

    let listener = TcpListener::from_std(listener).unwrap();
    let addr = listener.local_addr().unwrap();

    (listener, addr)
}

pub(crate) fn create_acceptor(setup: impl FnOnce(&mut SslAcceptorBuilder)) -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    acceptor
        .set_private_key_file("tests/key.pem", SslFiletype::PEM)
        .unwrap();

    acceptor
        .set_certificate_chain_file("tests/cert.pem")
        .unwrap();

    setup(&mut acceptor);

    acceptor.build()
}

pub(crate) async fn connect(
    addr: SocketAddr,
    setup: impl FnOnce(&mut SslConnectorBuilder) -> Result<(), ErrorStack>,
) -> Result<SslStream<TcpStream>, HandshakeError<TcpStream>> {
    let config = create_connector(setup).configure().unwrap();

    let stream = TcpStream::connect(&addr).await.unwrap();

    tokio_boring::connect(config, "localhost", stream).await
}

pub(crate) fn create_connector(
    setup: impl FnOnce(&mut SslConnectorBuilder) -> Result<(), ErrorStack>,
) -> SslConnector {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();

    setup(&mut connector).unwrap();

    connector.build()
}

pub(crate) async fn with_trivial_client_server_exchange(
    server_setup: impl FnOnce(&mut SslAcceptorBuilder),
) {
    let (stream, addr) = create_server(server_setup);

    let server = async {
        let mut stream = stream.await.unwrap();
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap();
    };

    let client = async {
        let mut stream = connect(addr, |builder| builder.set_ca_file("tests/cert.pem"))
            .await
            .unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}
