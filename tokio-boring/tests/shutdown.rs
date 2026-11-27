mod common;

use crate::common::{create_acceptor, create_connector};
use boring::ssl::{
    ErrorCode, SslAlert, SslContextBuilder, SslInfoCallbackMode, SslInfoCallbackValue, SslOptions,
    SslVersion,
};
use std::future::{poll_fn, Future};
use std::io;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_boring::SslStream;

#[derive(Debug)]
struct Transport {
    inner: DuplexStream,
    write_gate: Option<oneshot::Receiver<io::Result<()>>>,
    shutdown_gate: Option<oneshot::Receiver<io::Result<()>>>,
    reads: usize,
    writes: usize,
    shutdowns: usize,
}

impl Transport {
    fn gate_write(&mut self) -> oneshot::Sender<io::Result<()>> {
        let (release, gate) = oneshot::channel();
        self.write_gate = Some(gate);
        release
    }

    fn gate_shutdown(&mut self) -> oneshot::Sender<io::Result<()>> {
        let (release, gate) = oneshot::channel();
        self.shutdown_gate = Some(gate);
        release
    }
}

fn poll_gate(
    gate: &mut Option<oneshot::Receiver<io::Result<()>>>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if let Some(receiver) = gate {
        let result = ready!(Pin::new(receiver).poll(cx)).unwrap();
        *gate = None;
        return Poll::Ready(result);
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        ready!(poll_gate(&mut self.write_gate, cx))?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        ready!(poll_gate(&mut self.shutdown_gate, cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct CloseNotifyCounts {
    local: Arc<AtomicUsize>,
    peer: Arc<AtomicUsize>,
}

fn count_close_notify(builder: &mut SslContextBuilder, count: &Arc<AtomicUsize>) {
    let count = Arc::clone(count);
    builder.set_info_callback(move |_, mode, value| match (mode, value) {
        (SslInfoCallbackMode::READ_ALERT, SslInfoCallbackValue::Alert(alert))
            if alert.alert() == SslAlert::CLOSE_NOTIFY =>
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    });
}

async fn pair(
    version: SslVersion,
) -> (
    SslStream<Transport>,
    SslStream<DuplexStream>,
    CloseNotifyCounts,
) {
    let alerts = CloseNotifyCounts {
        local: Arc::new(AtomicUsize::new(0)),
        peer: Arc::new(AtomicUsize::new(0)),
    };
    let acceptor = create_acceptor(|builder| {
        builder.clear_options(SslOptions::NO_TLSV1_3);
        builder.set_min_proto_version(Some(version)).unwrap();
        builder.set_max_proto_version(Some(version)).unwrap();
        count_close_notify(builder, &alerts.peer);
    });
    let connector = create_connector(|builder| {
        builder.set_min_proto_version(Some(version))?;
        builder.set_max_proto_version(Some(version))?;
        count_close_notify(builder, &alerts.local);
        builder.set_ca_file("tests/cert.pem")
    });
    let (local, peer) = tokio::io::duplex(4096);
    let local = Transport {
        inner: local,
        write_gate: None,
        shutdown_gate: None,
        reads: 0,
        writes: 0,
        shutdowns: 0,
    };
    let (local, peer) = tokio::join!(
        async {
            tokio_boring::connect(connector.configure().unwrap(), "localhost", local)
                .await
                .unwrap()
        },
        async { tokio_boring::accept(&acceptor, peer).await.unwrap() },
    );
    assert_eq!(local.ssl().version2(), Some(version));
    (local, peer, alerts)
}

// Poll one shutdown future, then drop it so a subsequent call starts a fresh future.
async fn poll_shutdown(stream: &mut SslStream<Transport>) -> Poll<io::Result<()>> {
    let mut shutdown = pin!(stream.shutdown());
    poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await
}

async fn assert_close_notify(stream: &mut (impl AsyncRead + Unpin), alerts: &AtomicUsize) {
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(alerts.load(Ordering::Relaxed), 1);
}

async fn with_deadline(test: impl Future<Output = ()>) {
    timeout(Duration::from_secs(5), test).await.unwrap();
}

#[tokio::test]
async fn queued_reply_survives_transport_shutdown_retry() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;
        let release = local.get_mut().gate_shutdown();
        assert!(poll_shutdown(&mut local).await.is_pending());
        assert_eq!(local.get_ref().shutdowns, 1);
        assert_close_notify(&mut peer, &alerts.peer).await;

        const REPLY: &[u8] = b"reply after close_notify";
        peer.write_all(REPLY).await.unwrap();
        peer.flush().await.unwrap();
        release.send(Ok(())).unwrap();

        let result = poll_shutdown(&mut local).await;
        let mut reply = [0; REPLY.len()];
        local.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, REPLY);
        assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
        assert_eq!(local.get_ref().shutdowns, 2);

        peer.shutdown().await.unwrap();
        assert_close_notify(&mut local, &alerts.local).await;
    })
    .await;
}

#[tokio::test]
async fn transport_shutdown_completes_with_silent_peer() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;
        let release = local.get_mut().gate_shutdown();
        assert!(poll_shutdown(&mut local).await.is_pending());
        assert_close_notify(&mut peer, &alerts.peer).await;
        release.send(Ok(())).unwrap();

        let result = poll_shutdown(&mut local).await;
        assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
        assert_eq!(local.get_ref().shutdowns, 2);
    })
    .await;
}

#[tokio::test]
async fn transport_shutdown_waits_for_alert_write() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;
        let release_write = local.get_mut().gate_write();
        let release_shutdown = local.get_mut().gate_shutdown();
        let writes = local.get_ref().writes;

        assert!(poll_shutdown(&mut local).await.is_pending());
        assert_eq!(local.get_ref().writes, writes + 1);
        assert_eq!(local.get_ref().shutdowns, 0);
        assert_eq!(alerts.peer.load(Ordering::Relaxed), 0);

        release_write.send(Ok(())).unwrap();
        assert!(poll_shutdown(&mut local).await.is_pending());
        assert_eq!(local.get_ref().shutdowns, 1);
        assert_close_notify(&mut peer, &alerts.peer).await;

        release_shutdown.send(Ok(())).unwrap();
        local.shutdown().await.unwrap();
        assert_eq!(local.get_ref().shutdowns, 2);
        peer.shutdown().await.unwrap();
        assert_close_notify(&mut local, &alerts.local).await;
    })
    .await;
}

#[tokio::test]
async fn transport_shutdown_propagates_error_after_pending_and_can_be_retried() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;
        let release = local.get_mut().gate_shutdown();
        assert!(poll_shutdown(&mut local).await.is_pending());
        assert_close_notify(&mut peer, &alerts.peer).await;
        release
            .send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport shutdown failure",
            )))
            .unwrap();

        let error = local.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "transport shutdown failure");
        assert_eq!(local.get_ref().shutdowns, 2);

        local.shutdown().await.unwrap();
        assert_eq!(local.get_ref().shutdowns, 3);
    })
    .await;
}

#[tokio::test]
async fn alert_write_failure_prevents_transport_shutdown() {
    with_deadline(async {
        let (mut local, _peer, _alerts) = pair(SslVersion::TLS1_3).await;
        let release_write = local.get_mut().gate_write();
        assert!(poll_shutdown(&mut local).await.is_pending());
        release_write
            .send(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "TLS alert write failure",
            )))
            .unwrap();

        let error = local.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "TLS alert write failure");
        assert_eq!(local.get_ref().shutdowns, 0);
    })
    .await;
}

#[tokio::test]
async fn repeated_shutdown_only_polls_the_transport_writer() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;

        local.shutdown().await.unwrap();
        assert_eq!(local.get_ref().shutdowns, 1);
        assert_close_notify(&mut peer, &alerts.peer).await;
        let reads = local.get_ref().reads;
        let writes = local.get_ref().writes;

        let result = poll_shutdown(&mut local).await;
        assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
        assert_eq!(local.get_ref().shutdowns, 2);
        assert_eq!(local.get_ref().reads, reads);
        assert_eq!(local.get_ref().writes, writes);
        assert_close_notify(&mut peer, &alerts.peer).await;
    })
    .await;
}

#[tokio::test]
async fn acknowledges_previously_received_close_notify() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;

        peer.shutdown().await.unwrap();
        assert_close_notify(&mut local, &alerts.local).await;
        local.shutdown().await.unwrap();
        assert_close_notify(&mut peer, &alerts.peer).await;
    })
    .await;
}

#[tokio::test]
async fn graceful_tls12_shutdown() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_2).await;
        local.write_all(b"request").await.unwrap();

        local.shutdown().await.unwrap();
        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        assert_eq!(alerts.peer.load(Ordering::Relaxed), 1);

        peer.shutdown().await.unwrap();
        assert_close_notify(&mut local, &alerts.local).await;
    })
    .await;
}

#[tokio::test]
async fn bare_transport_eof_has_no_close_notify() {
    with_deadline(async {
        let (mut local, mut peer, alerts) = pair(SslVersion::TLS1_3).await;

        local.get_mut().inner.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(alerts.peer.load(Ordering::Relaxed), 0);
    })
    .await;
}

#[tokio::test]
async fn fatal_tls_error_prevents_transport_shutdown() {
    with_deadline(async {
        let (mut local, mut peer, _alerts) = pair(SslVersion::TLS1_3).await;

        // Send a TLS record header with an invalid version on the raw transport.
        peer.get_mut().write_all(&[23, 0, 0, 0, 0]).await.unwrap();
        let read_error = local.read(&mut [0]).await.unwrap_err();
        let shutdown_error = local.shutdown().await.unwrap_err();
        for error in [read_error, shutdown_error] {
            let tls_error = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<boring::ssl::Error>())
                .unwrap();
            assert_eq!(tls_error.code(), ErrorCode::SSL);
        }
        assert_eq!(local.get_ref().shutdowns, 0);
    })
    .await;
}
