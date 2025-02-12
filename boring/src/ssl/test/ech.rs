use crate::hpke::HpkeKey;
use crate::ssl::ech::SslEchKeys;
use crate::ssl::test::server::{ClientSslBuilder, Server};
use crate::ssl::HandshakeError;

// For future reference, these configs are generated by building the bssl tool (the binary is built
// alongside boringssl) and running the following command:
//
// ./bssl generate-ech -out-ech-config-list ./list -out-ech-config ./config -out-private-key ./key
// -public-name ech.com -config-id 1
static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../test/echconfiglist");
static ECH_CONFIG: &[u8] = include_bytes!("../../../test/echconfig");
static ECH_KEY: &[u8] = include_bytes!("../../../test/echkey");

static ECH_CONFIG_2: &[u8] = include_bytes!("../../../test/echconfig-2");
static ECH_KEY_2: &[u8] = include_bytes!("../../../test/echkey-2");

fn bootstrap_ech(config: &[u8], key: &[u8], list: &[u8]) -> (Server, ClientSslBuilder) {
    let server = {
        let key = HpkeKey::dhkem_p256_sha256(key).unwrap();
        let mut ech_keys = SslEchKeys::new().unwrap();
        ech_keys.add_key(true, config, key).unwrap();

        let mut builder = Server::builder();
        builder.ctx().set_ech_keys(ech_keys).unwrap();

        builder.build()
    };

    let mut client = server.client_with_root_ca().build().builder();
    client.ssl().set_ech_config_list(list).unwrap();
    client.ssl().set_hostname("foobar.com").unwrap();

    (server, client)
}

#[test]
fn ech() {
    let (_server, client) = bootstrap_ech(ECH_CONFIG, ECH_KEY, ECH_CONFIG_LIST);

    let ssl_stream = client.connect();
    assert!(ssl_stream.ssl().ech_accepted())
}

#[test]
fn ech_rejection() {
    // Server is initialized using `ECH_CONFIG_2`, so using `ECH_CONFIG_LIST` instead of
    // `ECH_CONFIG_LIST_2` should trigger rejection.
    let (_server, client) = bootstrap_ech(ECH_CONFIG_2, ECH_KEY_2, ECH_CONFIG_LIST);

    let HandshakeError::Failure(failed_ssl_stream) = client.connect_err() else {
        panic!("wrong HandshakeError failure variant!");
    };
    assert_eq!(
        failed_ssl_stream.ssl().get_ech_name_override(),
        Some(b"ech.com".to_vec().as_ref())
    );
    assert!(failed_ssl_stream.ssl().get_ech_retry_configs().is_some());
    assert!(!failed_ssl_stream.ssl().ech_accepted())
}
