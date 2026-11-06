use std::sync::{Arc, Mutex};

use boring::ssl::SslMethod;
use futures::future;
use tokio::net::TcpStream;
use tokio_boring::client::{AsTarget, Connector, Target};

mod common;

use self::common::{create_acceptor, create_listener};

struct TestTarget {
    peer_name: String,
    port: u16,
    callback_value: &'static str,
}

impl AsTarget for TestTarget {
    fn as_target(&self) -> Target<'_> {
        Target::new(&self.peer_name, self.port)
    }
}

#[tokio::test]
async fn resumes_sessions_and_isolates_targets_and_partitions() {
    let (listener, addr) = create_listener();
    let acceptor = create_acceptor(|_| ());
    let callbacks = Arc::new(Mutex::new(Vec::new()));

    let server = async move {
        for _ in 0..4 {
            let stream = listener.accept().await.unwrap().0;
            tokio_boring::accept(&acceptor, stream).await.unwrap();
        }
    };

    let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file("tests/cert.pem").unwrap();
    let mut connector = Connector::<TestTarget, (&'static str, u8)>::new(builder).unwrap();
    connector.on_config({
        let callbacks = Arc::clone(&callbacks);
        move |_, target| {
            assert_eq!(target.callback_value, "context");
            callbacks.lock().unwrap().push("config");
            Ok(())
        }
    });
    connector.on_ssl({
        let callbacks = Arc::clone(&callbacks);
        move |_, target| {
            assert_eq!(target.callback_value, "context");
            callbacks.lock().unwrap().push("ssl");
            Ok(())
        }
    });

    let client = async move {
        let target = TestTarget {
            peer_name: "localhost".to_owned(),
            port: addr.port(),
            callback_value: "context",
        };
        let stream = connector
            .connect_partitioned(
                &target,
                ("tenant-a", 1),
                TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        assert!(!stream.ssl().session_reused());
        drop(stream);

        let cloned = connector.clone();
        let stream = cloned
            .connect_partitioned(
                &target,
                ("tenant-a", 1),
                TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        assert!(stream.ssl().session_reused());
        drop(stream);

        let stream = connector
            .connect_partitioned(
                &target,
                ("tenant-b", 1),
                TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        assert!(!stream.ssl().session_reused());
        drop(stream);

        let other_target = TestTarget {
            peer_name: "localhost".to_owned(),
            port: addr.port().wrapping_add(1),
            callback_value: "context",
        };
        let stream = connector
            .connect_partitioned(
                &other_target,
                ("tenant-a", 1),
                TcpStream::connect(addr).await.unwrap(),
            )
            .await
            .unwrap();
        assert!(!stream.ssl().session_reused());
    };

    future::join(server, client).await;

    assert_eq!(
        *callbacks.lock().unwrap(),
        ["config", "ssl", "config", "ssl", "config", "ssl", "config", "ssl"]
    );
}

#[tokio::test]
async fn zero_capacity_disables_session_caching() {
    let (listener, addr) = create_listener();
    let acceptor = create_acceptor(|_| ());

    let server = async move {
        for _ in 0..2 {
            let stream = listener.accept().await.unwrap().0;
            tokio_boring::accept(&acceptor, stream).await.unwrap();
        }
    };

    let mut builder = boring::ssl::SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_ca_file("tests/cert.pem").unwrap();
    let connector = Connector::<Target<'static>>::with_session_cache_capacity(builder, 0).unwrap();

    let client = async move {
        let target = Target::new("localhost", addr.port());

        for _ in 0..2 {
            let stream = connector
                .connect(&target, TcpStream::connect(addr).await.unwrap())
                .await
                .unwrap();
            assert!(!stream.ssl().session_reused());
        }
    };

    future::join(server, client).await;
}
