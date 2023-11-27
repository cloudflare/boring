use boring::ssl::ClientHello;
use futures::future;
use tokio::task::yield_now;
use tokio_boring::{AsyncSelectCertError, BoxSelectCertFinish, BoxSelectCertFuture};

mod common;

use self::common::{connect, create_server, with_trivial_client_server_exchange};

#[tokio::test]
async fn test_async_select_certificate_callback_trivial() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_select_certificate_callback(|_| {
            Ok(Box::pin(async {
                Ok(Box::new(|_: ClientHello<'_>| Ok(())) as BoxSelectCertFinish)
            }))
        });
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_yield() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_select_certificate_callback(|_| {
            Ok(Box::pin(async {
                yield_now().await;

                Ok(Box::new(|_: ClientHello<'_>| Ok(())) as BoxSelectCertFinish)
            }))
        });
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_return_error() {
    with_async_select_certificate_callback_error(|_| Err(AsyncSelectCertError)).await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_future_error() {
    with_async_select_certificate_callback_error(|_| {
        Ok(Box::pin(async move { Err(AsyncSelectCertError) }))
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_future_yield_error() {
    with_async_select_certificate_callback_error(|_| {
        Ok(Box::pin(async move {
            yield_now().await;

            Err(AsyncSelectCertError)
        }))
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_finish_error() {
    with_async_select_certificate_callback_error(|_| {
        Ok(Box::pin(async move {
            yield_now().await;

            Ok(Box::new(|_: ClientHello<'_>| Err(AsyncSelectCertError)) as BoxSelectCertFinish)
        }))
    })
    .await;
}

async fn with_async_select_certificate_callback_error(
    callback: impl Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertFuture, AsyncSelectCertError>
        + Send
        + Sync
        + 'static,
) {
    let (stream, addr) = create_server(|builder| {
        builder.set_async_select_certificate_callback(callback);
    });

    let server = async {
        let _err = stream.await.unwrap_err();
    };

    let client = async {
        let _err = connect(addr, |builder| builder.set_ca_file("tests/cert.pem"))
            .await
            .unwrap_err();
    };

    future::join(server, client).await;
}
