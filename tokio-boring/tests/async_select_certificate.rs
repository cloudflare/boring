use boring::hpke::HpkeKey;
use boring::ssl::{ClientHello, NameType, SslEchKeys};
use futures::future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::task::yield_now;
use tokio_boring::{
    AsyncSelectCertError, BoxSelectCertActionFinish, BoxSelectCertActionFuture,
    BoxSelectCertFinish, BoxSelectCertFuture, SelectCertAction,
};

mod common;

use self::common::{connect, create_connector, create_server, with_trivial_client_server_exchange};

static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../boring/test/echconfiglist");
static ECH_CONFIG: &[u8] = include_bytes!("../../boring/test/echconfig");
static ECH_KEY: &[u8] = include_bytes!("../../boring/test/echkey");

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
async fn test_async_select_certificate_callback_with_action() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_select_certificate_callback_with_action(|_| {
            Ok(Box::pin(async {
                yield_now().await;
                Ok(Box::new(|_: ClientHello<'_>| Ok(SelectCertAction::Success))
                    as BoxSelectCertActionFinish)
            }))
        });
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_with_action_ech_disable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let future_calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let (stream, addr) = create_server({
        let calls = calls.clone();
        let future_calls = future_calls.clone();
        let observations = observations.clone();
        move |builder| {
            let key = HpkeKey::dhkem_p256_sha256(ECH_KEY).unwrap();
            let mut ech_keys_builder = SslEchKeys::builder().unwrap();
            ech_keys_builder.add_key(true, ECH_CONFIG, key).unwrap();
            let ech_keys = ech_keys_builder.build();
            builder.set_ech_keys(&ech_keys).unwrap();

            let calls = calls.clone();
            let future_calls = future_calls.clone();
            let observations = observations.clone();
            builder.set_async_select_certificate_callback_with_action(move |_| {
                let calls = calls.clone();
                future_calls.fetch_add(1, Ordering::Relaxed);
                let observations = observations.clone();
                Ok(Box::pin(async move {
                    yield_now().await;
                    Ok(Box::new(move |client_hello: ClientHello<'_>| {
                        observations.lock().unwrap().push((
                            client_hello.ssl().ech_accepted(),
                            client_hello
                                .ssl()
                                .servername(NameType::HOST_NAME)
                                .map(str::to_owned),
                        ));
                        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                            Ok(SelectCertAction::DisableEch)
                        } else {
                            Ok(SelectCertAction::Success)
                        }
                    }) as BoxSelectCertActionFinish)
                }))
            });
        }
    });

    let server = async {
        stream.await.unwrap_err();
    };

    let client = async {
        let connector = create_connector(|builder| builder.set_ca_file("tests/cert.pem"));
        let mut config = connector.configure().unwrap();
        config.set_ech_config_list(ECH_CONFIG_LIST).unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();
        tokio_boring::connect(config, "localhost", stream)
            .await
            .unwrap_err();
    };

    future::join(server, client).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(future_calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        *observations.lock().unwrap(),
        vec![
            (true, Some("localhost".to_owned())),
            (false, Some("ech.com".to_owned())),
        ]
    );
}

#[tokio::test]
async fn test_async_select_certificate_callback_with_action_return_error() {
    with_async_select_certificate_callback_action_error(|_| Err(AsyncSelectCertError)).await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_with_action_future_error() {
    with_async_select_certificate_callback_action_error(|_| {
        Ok(Box::pin(async move { Err(AsyncSelectCertError) }))
    })
    .await;
}

#[tokio::test]
async fn test_async_select_certificate_callback_with_action_finish_error() {
    with_async_select_certificate_callback_action_error(|_| {
        Ok(Box::pin(async move {
            yield_now().await;

            Ok(Box::new(|_: ClientHello<'_>| Err(AsyncSelectCertError))
                as BoxSelectCertActionFinish)
        }))
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

async fn with_async_select_certificate_callback_action_error(
    callback: impl Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertActionFuture, AsyncSelectCertError>
        + Send
        + Sync
        + 'static,
) {
    let (stream, addr) = create_server(|builder| {
        builder.set_async_select_certificate_callback_with_action(callback);
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
