use crate::hash::MessageDigest;
use crate::ssl::test::Server;
use crate::ssl::SslVerifyMode;

#[test]
fn error_when_trusted_but_callback_returns_false() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_cert_verify_callback(|x509| {
        // The cert is OK
        assert!(x509.verify_cert().unwrap());
        assert!(x509.current_cert().is_some());
        assert!(x509.verify_result().is_ok());
        // But we return false
        false
    });

    client.connect_err();
}

#[test]
fn no_error_when_untrusted_but_callback_returns_true() {
    let server = Server::builder().build();
    let mut client = server.client();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_cert_verify_callback(|x509| {
        // The cert is not OK
        assert!(!x509.verify_cert().unwrap());
        assert!(x509.current_cert().is_some());
        assert!(x509.verify_result().is_err());
        // But we return true
        true
    });

    client.connect();
}

#[test]
fn no_error_when_trusted_and_callback_returns_true() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_cert_verify_callback(|x509| {
        // The cert is OK
        assert!(x509.verify_cert().unwrap());
        assert!(x509.current_cert().is_some());
        assert!(x509.verify_result().is_ok());
        // And we return true
        true
    });
    client.connect();
}

#[test]
fn callback_receives_correct_certificate() {
    let server = Server::builder().build();
    let mut client = server.client();
    let expected = "59172d9313e84459bcff27f967e79e6e9217e584";
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_cert_verify_callback(move |x509| {
        assert!(!x509.verify_cert().unwrap());
        assert!(x509.current_cert().is_some());
        assert!(x509.verify_result().is_err());
        let cert = x509.current_cert().unwrap();
        let digest = cert.digest(MessageDigest::sha1()).unwrap();
        assert_eq!(hex::encode(digest), expected);
        true
    });

    client.connect();
}

#[test]
fn callback_receives_correct_chain() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
    let leaf_sha1 = "59172d9313e84459bcff27f967e79e6e9217e584";
    let root_sha1 = "c0cbdf7cdd03c9773e5468e1f6d2da7d5cbb1875";
    client.ctx().set_verify(SslVerifyMode::PEER);
    client.ctx().set_cert_verify_callback(move |x509| {
        assert!(x509.verify_cert().unwrap());
        assert!(x509.current_cert().is_some());
        assert!(x509.verify_result().is_ok());
        let chain = x509.chain().unwrap();
        assert!(chain.len() == 2);
        let leaf_cert = chain.get(0).unwrap();
        let leaf_digest = leaf_cert.digest(MessageDigest::sha1()).unwrap();
        assert_eq!(hex::encode(leaf_digest), leaf_sha1);
        let root_cert = chain.get(1).unwrap();
        let root_digest = root_cert.digest(MessageDigest::sha1()).unwrap();
        assert_eq!(hex::encode(root_digest), root_sha1);
        true
    });

    client.connect();
}
