use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::rsa::Padding;
use boring::sign::{RsaPssSaltlen, Signer};
use boring::ssl::{SslRef, SslSignatureAlgorithm};
use futures::future;
use tokio::task::yield_now;
use tokio_boring::{AsyncPrivateKeyMethod, AsyncPrivateKeyMethodError, BoxPrivateKeyMethodFuture};

mod common;

use self::common::{connect, create_server, with_trivial_client_server_exchange};

#[allow(clippy::type_complexity)]
struct Method {
    sign: Box<
        dyn Fn(
                &mut SslRef,
                &[u8],
                SslSignatureAlgorithm,
                &mut [u8],
            ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>
            + Send
            + Sync
            + 'static,
    >,
    decrypt: Box<
        dyn Fn(
                &mut SslRef,
                &[u8],
                &mut [u8],
            ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>
            + Send
            + Sync
            + 'static,
    >,
}

impl Method {
    fn new() -> Self {
        Self {
            sign: Box::new(|_, _, _, _| unreachable!("called sign")),
            decrypt: Box::new(|_, _, _| unreachable!("called decrypt")),
        }
    }

    fn sign(
        mut self,
        sign: impl Fn(
                &mut SslRef,
                &[u8],
                SslSignatureAlgorithm,
                &mut [u8],
            ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.sign = Box::new(sign);

        self
    }

    #[allow(dead_code)]
    fn decrypt(
        mut self,
        decrypt: impl Fn(
                &mut SslRef,
                &[u8],
                &mut [u8],
            ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.decrypt = Box::new(decrypt);

        self
    }
}

impl AsyncPrivateKeyMethod for Method {
    fn sign(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        signature_algorithm: SslSignatureAlgorithm,
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError> {
        (self.sign)(ssl, input, signature_algorithm, output)
    }

    fn decrypt(
        &self,
        ssl: &mut SslRef,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<BoxPrivateKeyMethodFuture, AsyncPrivateKeyMethodError> {
        (self.decrypt)(ssl, input, output)
    }
}

#[tokio::test]
async fn test_sign_failure() {
    with_async_private_key_method_error(
        Method::new().sign(|_, _, _, _| Err(AsyncPrivateKeyMethodError)),
    )
    .await;
}

#[tokio::test]
async fn test_sign_future_failure() {
    with_async_private_key_method_error(
        Method::new().sign(|_, _, _, _| Ok(Box::pin(async { Err(AsyncPrivateKeyMethodError) }))),
    )
    .await;
}

#[tokio::test]
async fn test_sign_future_yield_failure() {
    with_async_private_key_method_error(Method::new().sign(|_, _, _, _| {
        Ok(Box::pin(async {
            yield_now().await;

            Err(AsyncPrivateKeyMethodError)
        }))
    }))
    .await;
}

#[tokio::test]
async fn test_sign_ok() {
    with_trivial_client_server_exchange(|builder| {
        builder.set_async_private_key_method(Method::new().sign(
            |_, input, signature_algorithm, _| {
                assert_eq!(
                    signature_algorithm,
                    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                );

                let input = input.to_owned();

                Ok(Box::pin(async move {
                    Ok(Box::new(move |_: &mut SslRef, output: &mut [u8]| {
                        Ok(sign_with_default_config(&input, output))
                    }) as Box<_>)
                }))
            },
        ));
    })
    .await;
}

fn sign_with_default_config(input: &[u8], output: &mut [u8]) -> usize {
    let pkey = PKey::private_key_from_pem(include_bytes!("key.pem")).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();

    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .unwrap();

    signer.update(input).unwrap();

    signer.sign(output).unwrap()
}

async fn with_async_private_key_method_error(method: Method) {
    let (stream, addr) = create_server(move |builder| {
        builder.set_async_private_key_method(method);
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
