//! Hyper SSL support via OpenSSL.
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use crate::cache::{SessionCache, SessionKey};
use antidote::Mutex;
use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod, SslSessionCacheMode,
};
use http::uri::Scheme;
use hyper::client::connect::{Connected, Connection};
#[cfg(feature = "runtime")]
use hyper::client::HttpConnector;
use hyper::service::Service;
use hyper::Uri;
use once_cell::sync::OnceCell;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{error::Error, fmt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_boring::SslStream;
use tower_layer::Layer;

mod cache;
#[cfg(test)]
mod test;

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: OnceCell<Index<Ssl, SessionKey>> = OnceCell::new();
    IDX.get_or_try_init(Ssl::new_ex_index).map(|v| *v)
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache>>,
    #[allow(clippy::type_complexity)]
    callback: Option<
        Arc<dyn Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + Sync + Send>,
    >,
}

impl Inner {
    fn setup_ssl(&self, uri: &Uri, host: &str) -> Result<ConnectConfiguration, ErrorStack> {
        let mut conf = self.ssl.configure()?;

        if let Some(ref callback) = self.callback {
            callback(&mut conf, uri)?;
        }

        let key = SessionKey {
            host: host.to_string(),
            port: uri.port_u16().unwrap_or(443),
        };

        if let Some(session) = self.cache.lock().get(&key) {
            unsafe {
                conf.set_session(&session)?;
            }
        }

        let idx = key_index()?;
        conf.set_ex_data(idx, key);

        Ok(conf)
    }
}

/// A layer which wraps services in an `HttpsConnector`.
pub struct HttpsLayer {
    inner: Inner,
}

impl HttpsLayer {
    /// Creates a new `HttpsLayer` with default settings.
    ///
    /// ALPN is configured to support both HTTP/1 and HTTP/1.1.
    pub fn new() -> Result<HttpsLayer, ErrorStack> {
        let mut ssl = SslConnector::builder(SslMethod::tls())?;

        ssl.set_alpn_protos(b"\x02h2\x08http/1.1")?;

        Self::with_connector(ssl)
    }

    /// Creates a new `HttpsLayer`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(mut ssl: SslConnectorBuilder) -> Result<HttpsLayer, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::new()));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        ssl.set_new_session_callback({
            let cache = cache.clone();
            move |ssl, session| {
                if let Some(key) = key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        ssl.set_remove_session_callback({
            let cache = cache.clone();
            move |_, session| cache.lock().remove(session)
        });

        Ok(HttpsLayer {
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: None,
            },
        })
    }

    /// Registers a callback which can customize the configuration of each connection.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<S> Layer<S> for HttpsLayer {
    type Service = HttpsConnector<S>;

    fn layer(&self, inner: S) -> HttpsConnector<S> {
        HttpsConnector {
            http: inner,
            inner: self.inner.clone(),
        }
    }
}

/// A Connector using OpenSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

#[cfg(feature = "runtime")]
impl HttpsConnector<HttpConnector> {
    /// Creates a a new `HttpsConnector` using default settings.
    ///
    /// The Hyper `HttpConnector` is used to perform the TCP socket connection. ALPN is configured to support both
    /// HTTP/2 and HTTP/1.1.
    ///
    /// Requires the `runtime` Cargo feature.
    pub fn new() -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        HttpsLayer::new().map(|l| l.layer(http))
    }
}

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = T> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// The session cache configuration of `ssl` will be overwritten.
    pub fn with_connector(
        http: S,
        ssl: SslConnectorBuilder,
    ) -> Result<HttpsConnector<S>, ErrorStack> {
        HttpsLayer::with_connector(ssl).map(|l| l.layer(http))
    }

    /// Registers a callback which can customize the configuration of each connection.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.callback = Some(Arc::new(callback));
    }
}

impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    S::Response: AsyncRead + AsyncWrite + Connection + Unpin + Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<S::Response>;
    type Error = Box<dyn Error + Sync + Send>;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let is_tls_scheme = uri
            .scheme()
            .map(|s| s == &Scheme::HTTPS || s.as_str() == "wss")
            .unwrap_or(false);

        let tls_setup = if is_tls_scheme {
            Some((self.inner.clone(), uri.clone()))
        } else {
            None
        };

        let connect = self.http.call(uri);

        let f = async {
            let conn = connect.await.map_err(Into::into)?;

            let (inner, uri) = match tls_setup {
                Some((inner, uri)) => (inner, uri),
                None => return Ok(MaybeHttpsStream::Http(conn)),
            };

            let mut host = uri.host().ok_or("URI missing host")?;

            // If `host` is an IPv6 address, we must strip away the square brackets that surround
            // it (otherwise, boring will fail to parse the host as an IP address, eventually
            // causing the handshake to fail due a hostname verification error).
            if !host.is_empty() {
                let last = host.len() - 1;
                let mut chars = host.chars();

                if let (Some('['), Some(']')) = (chars.next(), chars.last()) {
                    if host[1..last].parse::<net::Ipv6Addr>().is_ok() {
                        host = &host[1..last];
                    }
                }
            }

            let config = inner.setup_ssl(&uri, host)?;
            let stream = tokio_boring::connect(config, host, conn).await?;

            Ok(MaybeHttpsStream::Https(stream))
        };

        Box::pin(f)
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> AsyncRead for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(ctx, buf),
        }
    }
}

impl<T> AsyncWrite for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(ctx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(ctx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(ctx),
        }
    }
}

impl<T> Connection for MaybeHttpsStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let mut connected = s.get_ref().connected();

                if s.ssl().selected_alpn_protocol() == Some(b"h2") {
                    connected = connected.negotiated_h2();
                }

                connected
            }
        }
    }
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}
