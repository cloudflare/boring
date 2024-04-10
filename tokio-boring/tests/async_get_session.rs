use boring::ssl::{SslOptions, SslRef, SslSession, SslSessionCacheMode, SslVersion};
use futures::future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tokio::net::TcpStream;
use tokio::task::yield_now;
use tokio_boring::BoxGetSessionFinish;

mod common;

use self::common::{create_acceptor, create_connector, create_listener};

#[tokio::test]
async fn test() {
    static FOUND_SESSION: AtomicBool = AtomicBool::new(false);
    static SERVER_SESSION_DER: OnceLock<Vec<u8>> = OnceLock::new();
    static CLIENT_SESSION_DER: OnceLock<Vec<u8>> = OnceLock::new();

    let (listener, addr) = create_listener();

    let acceptor = create_acceptor(move |builder| {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        builder.set_options(SslOptions::NO_TICKET);
        builder
            .set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
        builder.set_new_session_callback(|_, session| {
            SERVER_SESSION_DER.set(session.to_der().unwrap()).unwrap()
        });

        unsafe {
            builder.set_async_get_session_callback(|_, _| {
                let der = SERVER_SESSION_DER.get()?;

                Some(Box::pin(async move {
                    yield_now().await;

                    FOUND_SESSION.store(true, Ordering::SeqCst);

                    Some(Box::new(|_: &mut SslRef, _: &[u8]| {
                        Some(SslSession::from_der(der).unwrap())
                    }) as BoxGetSessionFinish)
                }))
            });
        }
    });

    let connector = create_connector(|builder| {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(|_, session| {
            CLIENT_SESSION_DER.set(session.to_der().unwrap()).unwrap()
        });

        builder.set_ca_file("tests/cert.pem")
    });

    let server = async move {
        tokio_boring::accept(&acceptor, listener.accept().await.unwrap().0)
            .await
            .unwrap();

        assert!(SERVER_SESSION_DER.get().is_some());
        assert!(!FOUND_SESSION.load(Ordering::SeqCst));

        tokio_boring::accept(&acceptor, listener.accept().await.unwrap().0)
            .await
            .unwrap();

        assert!(FOUND_SESSION.load(Ordering::SeqCst));
    };

    let client = async move {
        tokio_boring::connect(
            connector.configure().unwrap(),
            "localhost",
            TcpStream::connect(&addr).await.unwrap(),
        )
        .await
        .unwrap();

        let der = CLIENT_SESSION_DER.get().unwrap();

        let mut config = connector.configure().unwrap();

        unsafe {
            config
                .set_session(&SslSession::from_der(der).unwrap())
                .unwrap();
        }

        tokio_boring::connect(
            config,
            "localhost",
            TcpStream::connect(&addr).await.unwrap(),
        )
        .await
        .unwrap();
    };

    future::join(server, client).await;
}
