use boring::ssl::{BoxCustomVerifyFinish, BoxCustomVerifyFuture, SslAlert, SslRef, SslVerifyMode};
use futures::future;
use tokio::task::yield_now;

mod common;

use self::common::{connect, create_server, with_trivial_client_server_exchange};

#[tokio::test]
async fn test_async_custom_verify_callback_trivial() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Ok(Box::pin(async {
                Ok(Box::new(|_: &mut _| Ok(())) as BoxCustomVerifyFinish)
            }))
        });
    })
    .await;
}

#[tokio::test]
async fn test_async_custom_verify_callback_yield() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Ok(Box::pin(async {
                yield_now().await;

                Ok(Box::new(|_: &mut _| Ok(())) as BoxCustomVerifyFinish)
            }))
        });
    })
    .await;
}

#[tokio::test]
async fn test_async_custom_verify_callback_return_error() {
    with_async_custom_verify_callback_error(|_| Err(SslAlert::CERTIFICATE_REVOKED)).await;
}

#[tokio::test]
async fn test_async_custom_verify_callback_future_error() {
    with_async_custom_verify_callback_error(|_| {
        Ok(Box::pin(async move { Err(SslAlert::CERTIFICATE_REVOKED) }))
    })
    .await;
}

#[tokio::test]
async fn test_async_custom_verify_callback_future_yield_error() {
    with_async_custom_verify_callback_error(|_| {
        Ok(Box::pin(async move {
            yield_now().await;

            Err(SslAlert::CERTIFICATE_REVOKED)
        }))
    })
    .await;
}

#[tokio::test]
async fn test_async_custom_verify_callback_finish_error() {
    with_async_custom_verify_callback_error(|_| {
        Ok(Box::pin(async move {
            yield_now().await;

            Ok(Box::new(|_: &mut _| Err(SslAlert::CERTIFICATE_REVOKED)) as BoxCustomVerifyFinish)
        }))
    })
    .await;
}

async fn with_async_custom_verify_callback_error(
    callback: impl Fn(&mut SslRef) -> Result<BoxCustomVerifyFuture, SslAlert> + Send + Sync + 'static,
) {
    let (stream, addr) = create_server(|_| {});

    let server = async {
        let err = stream.await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS handshake failed [SSLV3_ALERT_CERTIFICATE_REVOKED]"
        );
    };

    let client = async {
        let _err = connect(addr, |builder| {
            builder.set_async_custom_verify_callback(SslVerifyMode::PEER, callback);
            builder.set_ca_file("tests/cert.pem")
        })
        .await
        .unwrap_err();
    };

    future::join(server, client).await;
}
