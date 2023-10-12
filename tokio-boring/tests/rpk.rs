#[cfg(feature = "rpk")]
mod test_rpk {
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslConnector};
    use futures::future;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_boring::{HandshakeError, SslStream};

    fn create_server() -> (
        impl Future<Output = Result<SslStream<TcpStream>, HandshakeError<TcpStream>>>,
        SocketAddr,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();

        listener.set_nonblocking(true).unwrap();

        let listener = TcpListener::from_std(listener).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = async move {
            let mut acceptor = SslAcceptor::rpk().unwrap();
            let pkey = std::fs::read("tests/key.pem").unwrap();
            let pkey = PKey::private_key_from_pem(&pkey).unwrap();
            let cert = std::fs::read("tests/pubkey.der").unwrap();

            acceptor.set_rpk_certificate(&cert).unwrap();
            acceptor.set_null_chain_private_key(&pkey).unwrap();

            let acceptor = acceptor.build();

            let stream = listener.accept().await.unwrap().0;

            tokio_boring::accept(&acceptor, stream).await
        };

        (server, addr)
    }

    #[tokio::test]
    async fn server_rpk() {
        let (stream, addr) = create_server();

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
            let mut connector = SslConnector::rpk_builder().unwrap();
            let cert = std::fs::read("tests/pubkey.der").unwrap();

            connector.set_rpk_certificate(&cert).unwrap();
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

    #[tokio::test]
    async fn client_rpk_unknown_cert() {
        let (stream, addr) = create_server();

        let server = async {
            assert!(stream.await.is_err());
        };

        let client = async {
            let mut connector = SslConnector::rpk_builder().unwrap();
            let cert = std::fs::read("tests/pubkey2.der").unwrap();

            connector.set_rpk_certificate(&cert).unwrap();
            let config = connector.build().configure().unwrap();

            let stream = TcpStream::connect(&addr).await.unwrap();

            let err = tokio_boring::connect(config, "localhost", stream)
                .await
                .unwrap_err();

            // NOTE: smoke test for https://github.com/cloudflare/boring/issues/140
            let _ = err.to_string();
        };

        future::join(server, client).await;
    }
}
