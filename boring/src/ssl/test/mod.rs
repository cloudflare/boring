use hex;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::error::ErrorStack;
use crate::hash::MessageDigest;
use crate::pkey::PKey;
use crate::srtp::SrtpProfileId;
use crate::ssl::test::server::Server;
use crate::ssl::SslVersion;
use crate::ssl::{self, SslCurve};
use crate::ssl::{
    ExtensionType, ShutdownResult, ShutdownState, Ssl, SslAcceptor, SslAcceptorBuilder,
    SslConnector, SslContext, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode,
};
use crate::x509::verify::X509CheckFlags;
use crate::x509::{X509Name, X509};

#[cfg(not(feature = "fips"))]
use super::CompliancePolicy;

mod custom_verify;
mod private_key_method;
mod server;
mod session;
mod verify;

static ROOT_CERT: &[u8] = include_bytes!("../../../test/root-ca.pem");
static CERT: &[u8] = include_bytes!("../../../test/cert.pem");
static KEY: &[u8] = include_bytes!("../../../test/key.pem");

#[test]
fn get_ctx_options() {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.options();
}

#[test]
fn set_ctx_options() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let opts = ctx.set_options(SslOptions::NO_TICKET);
    assert!(opts.contains(SslOptions::NO_TICKET));
}

#[test]
fn clear_ctx_options() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_options(SslOptions::NO_TICKET);
    let opts = ctx.clear_options(SslOptions::NO_TICKET);
    assert!(!opts.contains(SslOptions::NO_TICKET));
}

#[test]
fn zero_length_buffers() {
    let server = Server::builder().build();

    let mut s = server.client().connect();
    assert_eq!(s.write(&[]).unwrap(), 0);
    assert_eq!(s.read(&mut []).unwrap(), 0);
}

#[test]
fn peer_certificate() {
    let server = Server::builder().build();

    let s = server.client().connect();
    let cert = s.ssl().peer_certificate().unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();
    assert_eq!(
        hex::encode(fingerprint),
        "59172d9313e84459bcff27f967e79e6e9217e584"
    );
}

#[test]
fn pending() {
    let mut server = Server::builder();
    server.io_cb(|mut s| s.write_all(&[0; 10]).unwrap());
    let server = server.build();

    let mut s = server.client().connect();
    s.read_exact(&mut [0]).unwrap();

    assert_eq!(s.ssl().pending(), 9);
    assert_eq!(s.read(&mut [0; 10]).unwrap(), 9);
}

#[test]
fn state() {
    let server = Server::builder().build();

    let s = server.client().connect();
    // NOTE: Boring returs a placeholder string for state_string
    assert_eq!(s.ssl().state_string(), "!!!!!!");
    assert_eq!(
        s.ssl().state_string_long(),
        "SSL negotiation finished successfully"
    );
}

/// Tests that when both the client as well as the server use SRTP and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
fn test_connect_with_srtp_ctx() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        ctx.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
            .unwrap();
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_mtu(1500).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 60];
        stream
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    ctx.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
        .unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_mtu(1500).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 60];
    {
        let srtp_profile = stream.ssl().selected_srtp_profile().unwrap();
        assert_eq!("SRTP_AES128_CM_SHA1_80", srtp_profile.name());
        assert_eq!(SrtpProfileId::SRTP_AES128_CM_SHA1_80, srtp_profile.id());
    }
    stream
        .ssl()
        .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
        .expect("extract");

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf[..], buf2[..]);
}

/// Tests that when both the client as well as the server use SRTP and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
fn test_connect_with_srtp_ssl() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
            .unwrap();
        let mut profilenames = String::new();
        for profile in ssl.srtp_profiles().unwrap() {
            if !profilenames.is_empty() {
                profilenames.push(':');
            }
            profilenames += profile.name();
        }
        assert_eq!(
            "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
            profilenames
        );
        ssl.set_mtu(1500).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 60];
        stream
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
        .unwrap();
    ssl.set_mtu(1500).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 60];
    {
        let srtp_profile = stream.ssl().selected_srtp_profile().unwrap();
        assert_eq!("SRTP_AES128_CM_SHA1_80", srtp_profile.name());
        assert_eq!(SrtpProfileId::SRTP_AES128_CM_SHA1_80, srtp_profile.id());
    }
    stream
        .ssl()
        .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
        .expect("extract");

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf[..], buf2[..]);
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
fn test_alpn_server_advertise_multiple() {
    let mut server = Server::builder();
    server.ctx().set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
    });
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x08spdy/3.1").unwrap();
    let s = client.connect();
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"spdy/3.1"[..]));
}

#[test]
fn test_alpn_server_select_none_fatal() {
    let mut server = Server::builder();
    server.ctx().set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client)
            .ok_or(ssl::AlpnError::ALERT_FATAL)
    });
    server.should_error();
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    client.connect_err();
}

#[test]
fn test_alpn_server_select_none() {
    let mut server = Server::builder();
    server.ctx().set_alpn_select_callback(|_, client| {
        ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
    });
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    let s = client.connect();
    assert_eq!(None, s.ssl().selected_alpn_protocol());
}

#[test]
fn test_empty_alpn() {
    assert_eq!(ssl::select_next_proto(b"", b""), None);
    assert_eq!(ssl::select_next_proto(b"", b"\x08http/1.1"), None);
    assert_eq!(ssl::select_next_proto(b"\x08http/1.1", b""), None);
}

#[test]
fn test_alpn_server_unilateral() {
    let server = Server::builder().build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    let s = client.connect();
    assert_eq!(None, s.ssl().selected_alpn_protocol());
}

#[test]
fn test_select_cert_ok() {
    let mut server = Server::builder();
    server
        .ctx()
        .set_select_certificate_callback(|_client_hello| Ok(()));
    let server = server.build();

    let client = server.client();
    client.connect();
}

#[test]
fn test_select_cert_error() {
    let mut server = Server::builder();
    server.should_error();
    server
        .ctx()
        .set_select_certificate_callback(|_client_hello| Err(ssl::SelectCertError::ERROR));
    let server = server.build();

    let client = server.client();
    client.connect_err();
}

#[test]
fn test_select_cert_unknown_extension() {
    let mut server = Server::builder();
    let unknown_extension = std::sync::Arc::new(std::sync::Mutex::new(Some(vec![])));

    server.ctx().set_select_certificate_callback({
        let unknown = unknown_extension.clone();
        move |client_hello| {
            let ext = client_hello
                .get_extension(ExtensionType::SERVER_NAME)
                .map(ToOwned::to_owned);
            assert!(ext.is_none());
            *unknown.lock().unwrap() = ext;
            Ok(())
        }
    });

    let server = server.build();
    let client = server.client();

    client.connect();
    assert_eq!(unknown_extension.lock().unwrap().as_deref(), None);
}

#[test]
fn test_select_cert_alpn_extension() {
    let mut server = Server::builder();
    let alpn_extension = std::sync::Arc::new(std::sync::Mutex::new(None));
    server.ctx().set_select_certificate_callback({
        let alpn = alpn_extension.clone();
        move |client_hello| {
            *alpn.lock().unwrap() = Some(
                client_hello
                    .get_extension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                    .unwrap()
                    .to_owned(),
            );
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client();
    client.ctx().set_alpn_protos(b"\x06http/2").unwrap();
    client.connect();
    assert_eq!(
        alpn_extension.lock().unwrap().as_deref(),
        Some(&b"\x00\x07\x06http/2"[..]),
    );
}

#[test]
#[should_panic(expected = "blammo")]
fn write_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("blammo");
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn read_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("blammo");
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn flush_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("blammo");
        }
    }

    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let stream = ExplodingStream(server.connect_tcp());

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
fn refcount_ssl_context() {
    let mut ssl = {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ssl::Ssl::new(&ctx.build()).unwrap()
    };

    {
        let new_ctx_a = SslContext::builder(SslMethod::tls()).unwrap().build();
        let _new_ctx_b = ssl.set_ssl_context(&new_ctx_a);
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore)]
#[cfg_attr(all(target_os = "macos"), ignore)]
fn default_verify_paths() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    let ctx = ctx.build();
    let s = match TcpStream::connect("google.com:443") {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_hostname("google.com").unwrap();
    let mut socket = ssl.connect(s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn add_extra_chain_cert() {
    let cert = X509::from_pem(CERT).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_extra_chain_cert(cert).unwrap();
}

#[test]
fn verify_valid_hostname() {
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER);

    let mut client = client.build().builder();

    client.ssl().param_mut().set_host("foobar.com").unwrap();
    client.connect();
}

#[test]
fn verify_valid_hostname_with_wildcard() {
    let mut server = Server::builder();

    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER);

    let mut client = client.build().builder();
    client.ssl().param_mut().set_host("yes.foobar.com").unwrap();
    client.connect();
}

#[test]
fn verify_reject_underscore_hostname_with_wildcard() {
    let mut server = Server::builder();

    server.should_error();
    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER);

    let mut client = client.build().builder();
    client
        .ssl()
        .param_mut()
        .set_host("not_allowed.foobar.com")
        .unwrap();
    client.connect_err();
}

#[cfg(feature = "underscore-wildcards")]
#[test]
fn verify_allow_underscore_hostname_with_wildcard() {
    let mut server = Server::builder();

    server
        .ctx()
        .set_certificate_chain_file("test/cert-wildcard.pem")
        .unwrap();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER);

    let mut client = client.build().builder();

    client
        .ssl()
        .param_mut()
        .set_hostflags(X509CheckFlags::UNDERSCORE_WILDCARDS);
    client
        .ssl()
        .param_mut()
        .set_host("now_allowed.foobar.com")
        .unwrap();
    client.connect();
}

#[test]
fn verify_invalid_hostname() {
    let mut server = Server::builder();

    server.should_error();

    let server = server.build();
    let mut client = server.client_with_root_ca();

    client.ctx().set_verify(SslVerifyMode::PEER);

    let mut client = client.build().builder();
    client
        .ssl()
        .param_mut()
        .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    client.ssl().param_mut().set_host("bogus.com").unwrap();
    client.connect_err();
}

#[test]
fn connector_valid_hostname() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    let mut s = connector.build().connect("foobar.com", s).unwrap();
    s.read_exact(&mut [0]).unwrap();
}

#[test]
fn connector_invalid_hostname() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    connector.build().connect("bogus.com", s).unwrap_err();
}

#[test]
fn connector_invalid_no_hostname_verification() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();

    let s = server.connect_tcp();
    let mut s = connector
        .build()
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("bogus.com", s)
        .unwrap();
    s.read_exact(&mut [0]).unwrap();
}

#[test]
fn connector_no_hostname_still_verifies() {
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = server.connect_tcp();
    assert!(connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("fizzbuzz.com", s)
        .is_err());
}

#[test]
fn connector_no_hostname_can_disable_verify() {
    let server = Server::builder().build();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();

    let s = server.connect_tcp();
    let mut s = connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("foobar.com", s)
        .unwrap();
    s.read_exact(&mut [0]).unwrap();
}

fn test_mozilla_server(new: fn(SslMethod) -> Result<SslAcceptorBuilder, ErrorStack>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let mut acceptor = new(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let stream = listener.accept().unwrap().0;
        let mut stream = acceptor.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn connector_client_server_mozilla_intermediate() {
    test_mozilla_server(SslAcceptor::mozilla_intermediate);
}

#[test]
fn connector_client_server_mozilla_modern() {
    test_mozilla_server(SslAcceptor::mozilla_modern);
}

#[test]
fn connector_client_server_mozilla_intermediate_v5() {
    test_mozilla_server(SslAcceptor::mozilla_intermediate_v5);
}

#[test]
fn shutdown() {
    let mut server = Server::builder();
    server.io_cb(|mut s| {
        assert_eq!(s.read(&mut [0]).unwrap(), 0);
        assert_eq!(s.shutdown().unwrap(), ShutdownResult::Received);
    });
    let server = server.build();

    let mut s = server.client().connect();

    assert_eq!(s.get_shutdown(), ShutdownState::empty());
    assert_eq!(s.shutdown().unwrap(), ShutdownResult::Sent);
    assert_eq!(s.get_shutdown(), ShutdownState::SENT);
    assert_eq!(s.shutdown().unwrap(), ShutdownResult::Received);
    assert_eq!(
        s.get_shutdown(),
        ShutdownState::SENT | ShutdownState::RECEIVED
    );
}

#[test]
fn client_ca_list() {
    let names = X509Name::load_client_ca_file("test/root-ca.pem").unwrap();
    assert_eq!(names.len(), 1);

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_client_ca_list(names);
}

#[test]
fn keying_export() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let label = "EXPERIMENTAL test";
    let context = b"my context";

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 32];
        stream
            .ssl()
            .export_keying_material(&mut buf, label, Some(context))
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 32];
    stream
        .ssl()
        .export_keying_material(&mut buf, label, Some(context))
        .unwrap();

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf, buf2);
}

#[test]
fn no_version_overlap() {
    let mut server = Server::builder();
    server.ctx().set_min_proto_version(None).unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    assert_eq!(server.ctx().max_proto_version(), Some(SslVersion::TLS1_1));
    server.should_error();
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    assert_eq!(client.ctx().min_proto_version(), Some(SslVersion::TLS1_2));
    client.ctx().set_max_proto_version(None).unwrap();

    client.connect_err();
}

fn _check_kinds() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    is_send::<SslStream<TcpStream>>();
    is_sync::<SslStream<TcpStream>>();
}

#[test]
fn psk_ciphers() {
    const CIPHER: &str = "PSK-AES128-CBC-SHA";
    const PSK: &[u8] = b"thisisaverysecurekey";
    const CLIENT_IDENT: &[u8] = b"thisisaclient";
    static CLIENT_CALLED: AtomicBool = AtomicBool::new(false);
    static SERVER_CALLED: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();
    server.ctx().set_cipher_list(CIPHER).unwrap();
    server.ctx().set_psk_server_callback(|_, identity, psk| {
        assert!(identity.unwrap_or(&[]) == CLIENT_IDENT);
        psk[..PSK.len()].copy_from_slice(PSK);
        SERVER_CALLED.store(true, Ordering::SeqCst);
        Ok(PSK.len())
    });

    let server = server.build();

    let mut client = server.client();
    // This test relies on TLS 1.2 suites
    client.ctx().set_options(super::SslOptions::NO_TLSV1_3);
    client.ctx().set_cipher_list(CIPHER).unwrap();
    client
        .ctx()
        .set_psk_client_callback(move |_, _, identity, psk| {
            identity[..CLIENT_IDENT.len()].copy_from_slice(CLIENT_IDENT);
            identity[CLIENT_IDENT.len()] = 0;
            psk[..PSK.len()].copy_from_slice(PSK);
            CLIENT_CALLED.store(true, Ordering::SeqCst);
            Ok(PSK.len())
        });

    client.connect();

    assert!(CLIENT_CALLED.load(Ordering::SeqCst) && SERVER_CALLED.load(Ordering::SeqCst));
}

#[test]
fn sni_callback_swapped_ctx() {
    static CALLED_BACK: AtomicBool = AtomicBool::new(false);

    let mut server = Server::builder();

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_servername_callback(|_, _| {
        CALLED_BACK.store(true, Ordering::SeqCst);
        Ok(())
    });

    let keyed_ctx = mem::replace(server.ctx(), ctx).build();
    server.ssl_cb(move |ssl| ssl.set_ssl_context(&keyed_ctx).unwrap());

    let server = server.build();

    server.client().connect();

    assert!(CALLED_BACK.load(Ordering::SeqCst));
}

#[cfg(feature = "kx-safe-default")]
#[test]
fn client_set_default_curves_list() {
    let ssl_ctx = crate::ssl::SslContextBuilder::new(SslMethod::tls())
        .unwrap()
        .build();
    let mut ssl = Ssl::new(&ssl_ctx).unwrap();

    // Panics if Kyber768 missing in boringSSL.
    ssl.client_set_default_curves_list();
}

#[cfg(feature = "kx-safe-default")]
#[test]
fn server_set_default_curves_list() {
    let ssl_ctx = crate::ssl::SslContextBuilder::new(SslMethod::tls())
        .unwrap()
        .build();
    let mut ssl = Ssl::new(&ssl_ctx).unwrap();

    // Panics if Kyber768 missing in boringSSL.
    ssl.server_set_default_curves_list();
}

#[test]
fn get_curve() {
    let server = Server::builder().build();
    let client = server.client_with_root_ca();
    let client_stream = client.connect();
    let curve = client_stream.ssl().curve().expect("curve");
    assert!(curve.name().is_some());
}

#[test]
fn get_curve_name() {
    assert_eq!(SslCurve::SECP224R1.name(), Some("P-224"));
    assert_eq!(SslCurve::SECP256R1.name(), Some("P-256"));
    assert_eq!(SslCurve::SECP384R1.name(), Some("P-384"));
    assert_eq!(SslCurve::SECP521R1.name(), Some("P-521"));
    assert_eq!(SslCurve::X25519.name(), Some("X25519"));
}

#[cfg(not(feature = "kx-safe-default"))]
#[test]
fn set_curves() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_curves(&[
        SslCurve::SECP224R1,
        SslCurve::SECP256R1,
        SslCurve::SECP384R1,
        SslCurve::X25519,
    ])
    .expect("Failed to set curves");
}

#[test]
fn test_get_ciphers() {
    let ctx_builder = SslContext::builder(SslMethod::tls()).unwrap();
    let ctx_builder_ciphers: Vec<&str> = ctx_builder
        .ciphers()
        .unwrap()
        .into_iter()
        .map(|v| v.name())
        .collect();
    assert!(!(ctx_builder_ciphers.is_empty()));

    let ctx = ctx_builder.build();
    let ctx_ciphers: Vec<&str> = ctx
        .ciphers()
        .unwrap()
        .into_iter()
        .map(|v| v.name())
        .collect();
    assert!(!(ctx_ciphers.is_empty()));

    assert_eq!(ctx_builder_ciphers.len(), ctx_ciphers.len());

    for (ctx_builder_cipher, ctx_cipher) in ctx_builder_ciphers.into_iter().zip(ctx_ciphers) {
        assert_eq!(ctx_builder_cipher, ctx_cipher);
    }
}

#[test]
#[cfg(not(feature = "fips"))]
fn test_set_compliance() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_compliance_policy(CompliancePolicy::FIPS_202205)
        .unwrap();

    assert_eq!(ctx.max_proto_version().unwrap(), SslVersion::TLS1_3);
    assert_eq!(ctx.min_proto_version().unwrap(), SslVersion::TLS1_2);

    const FIPS_CIPHERS: [&str; 4] = [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ];

    let ciphers = ctx.ciphers().unwrap();
    assert_eq!(ciphers.len(), FIPS_CIPHERS.len());

    for cipher in ciphers.into_iter().zip(FIPS_CIPHERS) {
        assert_eq!(cipher.0.name(), cipher.1)
    }

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_compliance_policy(CompliancePolicy::WPA3_192_202304)
        .unwrap();

    assert_eq!(ctx.max_proto_version().unwrap(), SslVersion::TLS1_3);
    assert_eq!(ctx.min_proto_version().unwrap(), SslVersion::TLS1_2);

    const WPA3_192_CIPHERS: [&str; 2] = [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
    ];

    let ciphers = ctx.ciphers().unwrap();
    assert_eq!(ciphers.len(), WPA3_192_CIPHERS.len());

    for cipher in ciphers.into_iter().zip(WPA3_192_CIPHERS) {
        assert_eq!(cipher.0.name(), cipher.1)
    }

    ctx.set_compliance_policy(CompliancePolicy::NONE)
        .expect_err("Testing expect err if set compliance policy to NONE");
}

#[test]
fn drop_ex_data_in_context() {
    let index = SslContext::new_ex_index::<&'static str>().unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();

    assert_eq!(ctx.replace_ex_data(index, "comté"), None);
    assert_eq!(ctx.replace_ex_data(index, "camembert"), Some("comté"));
    assert_eq!(ctx.replace_ex_data(index, "raclette"), Some("camembert"));
}

#[test]
fn drop_ex_data_in_ssl() {
    let index = Ssl::new_ex_index::<&'static str>().unwrap();
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap().build();
    let mut ssl = Ssl::new(&ctx).unwrap();

    assert_eq!(ssl.replace_ex_data(index, "comté"), None);
    assert_eq!(ssl.replace_ex_data(index, "camembert"), Some("comté"));
    assert_eq!(ssl.replace_ex_data(index, "raclette"), Some("camembert"));
}
