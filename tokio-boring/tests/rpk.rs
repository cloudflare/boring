#![cfg(feature = "rpk")]

use boring::pkey::PKey;
use boring::ssl::{
    CertificateType, SslAcceptor, SslAlert, SslConnector, SslCredential, SslMethod, SslVerifyError,
    SslVerifyMode,
};
use futures::future;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
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
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        let private_key =
            PKey::private_key_from_pem(&std::fs::read("tests/key.pem").unwrap()).unwrap();
        let spki = std::fs::read("tests/pubkey.der").unwrap();

        acceptor
            .add_credential({
                let mut cred = SslCredential::new_raw_public_key().unwrap();

                cred.set_private_key(&private_key).unwrap();
                cred.set_spki_bytes(Some(&spki)).unwrap();

                &cred.build()
            })
            .unwrap();

        let acceptor = acceptor.build();

        let stream = listener.accept().await.unwrap().0;

        tokio_boring::accept(&acceptor, stream).await
    };

    (server, addr)
}

async fn connect(
    addr: SocketAddr,
    spki_path: &str,
    is_ok_cell: &Arc<OnceLock<bool>>,
) -> Result<SslStream<TcpStream>, HandshakeError<TcpStream>> {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    let spki = PKey::public_key_from_der(&std::fs::read(spki_path).unwrap()).unwrap();
    let is_ok_cell = Arc::clone(is_ok_cell);

    connector
        .set_server_certificate_types(&[CertificateType::RAW_PUBLIC_KEY])
        .unwrap();

    connector.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        let public_key = ssl
            .peer_pubkey()
            .ok_or(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))?;

        let is_ok = public_key.public_eq(&spki);

        is_ok_cell.set(is_ok).unwrap();

        if !is_ok {
            return Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE));
        }

        Ok(())
    });

    let config = connector.build().configure().unwrap();

    tokio_boring::connect(
        config,
        "localhost",
        TcpStream::connect(&addr).await.unwrap(),
    )
    .await
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
        let is_ok_cell = Arc::new(OnceLock::new());
        let mut stream = connect(addr, "tests/pubkey.der", &is_ok_cell)
            .await
            .unwrap();

        assert!(is_ok_cell.get().unwrap());

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
        let is_ok_cell = Arc::new(OnceLock::new());
        let err = connect(addr, "tests/pubkey2.der", &is_ok_cell)
            .await
            .unwrap_err();

        assert!(!is_ok_cell.get().unwrap());

        // NOTE: smoke test for https://github.com/cloudflare/boring/issues/140
        let _ = err.to_string();
    };

    future::join(server, client).await;
}
