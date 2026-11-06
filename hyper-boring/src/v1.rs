use crate::{HttpsLayerSettings, MaybeHttpsStream};
use boring::error::ErrorStack;
use boring::ssl::{ConnectConfiguration, SslConnector, SslConnectorBuilder, SslMethod, SslRef};
use http::uri::Scheme;
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring::client::{AsTarget, Connector, Target};
use tower_layer::Layer;
use tower_service::Service;

/// A Connector using BoringSSL to support `http` and `https` schemes.
#[derive(Clone)]
pub struct HttpsConnector<T> {
    http: T,
    inner: Inner,
}

impl HttpsConnector<HttpConnector> {
    /// Creates a a new `HttpsConnector` using default settings.
    ///
    /// The Hyper `HttpConnector` is used to perform the TCP socket connection. ALPN is configured to support both
    /// HTTP/2 and HTTP/1.1.
    pub fn new() -> Result<HttpsConnector<HttpConnector>, ErrorStack> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        HttpsLayer::new().map(|l| l.layer(http))
    }
}

impl<S, T> HttpsConnector<S>
where
    S: Service<Uri, Response = TokioIo<T>> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
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
    ///
    /// Unsuitable to change verify hostflags (with `config.param_mut().set_hostflags(…)`),
    /// as they are reset after the callback is executed. Use [`Self::set_ssl_callback`]
    /// instead.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner
            .ssl
            .on_config(move |config, target| callback(config, &target.uri));
    }

    /// Registers a callback which can customize the `Ssl` of each connection.
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner
            .ssl
            .on_ssl(move |ssl, target| callback(ssl, &target.uri));
    }
}

/// A layer which wraps services in an `HttpsConnector`.
pub struct HttpsLayer {
    inner: Inner,
}

#[derive(Clone)]
struct Inner {
    ssl: Connector<HttpTarget>,
}

struct HttpTarget {
    uri: Uri,
    peer_name: String,
}

impl HttpTarget {
    fn try_new(uri: Uri) -> Result<Self, &'static str> {
        let peer_name = uri.host().ok_or("URI missing host")?.to_owned();
        Ok(Self { uri, peer_name })
    }
}

impl AsTarget for HttpTarget {
    fn as_target(&self) -> Target<'_> {
        Target::new(&self.peer_name, self.uri.port_u16().unwrap_or(443))
    }
}

fn effective_session_cache_capacity(settings: &HttpsLayerSettings) -> usize {
    // Preserve the historical behavior where a configured capacity of zero retained one session
    // per target.
    settings.session_cache_capacity.max(1)
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
    pub fn with_connector(ssl: SslConnectorBuilder) -> Result<HttpsLayer, ErrorStack> {
        Self::with_connector_and_settings(ssl, HttpsLayerSettings::default())
    }

    /// Creates a new `HttpsLayer` with settings
    pub fn with_connector_and_settings(
        ssl: SslConnectorBuilder,
        settings: HttpsLayerSettings,
    ) -> Result<HttpsLayer, ErrorStack> {
        let session_cache_capacity = effective_session_cache_capacity(&settings);
        let ssl =
            Connector::<HttpTarget>::with_session_cache_capacity(ssl, session_cache_capacity)?;

        Ok(HttpsLayer {
            inner: Inner { ssl },
        })
    }

    /// Registers a callback which can customize the configuration of each connection.
    ///
    /// Unsuitable to change verify hostflags (with `config.param_mut().set_hostflags(…)`),
    /// as they are reset after the callback is executed. Use [`Self::set_ssl_callback`]
    /// instead.
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner
            .ssl
            .on_config(move |config, target| callback(config, &target.uri));
    }

    /// Registers a callback which can customize the `Ssl` of each connection.
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner
            .ssl
            .on_ssl(move |ssl, target| callback(ssl, &target.uri));
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

impl<T, S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri, Response = TokioIo<T>> + Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
    S::Future: Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Connection + Unpin + fmt::Debug + Sync + Send + 'static,
{
    type Response = MaybeHttpsStream<T>;
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
            Some((self.inner.ssl.clone(), uri.clone()))
        } else {
            None
        };

        let connect = self.http.call(uri);

        let f = async {
            let conn = connect.await.map_err(Into::into)?.into_inner();

            let Some((ssl, uri)) = tls_setup else {
                return Ok(MaybeHttpsStream::Http(conn));
            };

            let target = HttpTarget::try_new(uri)?;
            let stream = ssl.connect(&target, conn).await?;

            Ok(MaybeHttpsStream::Https(stream))
        };

        Box::pin(f)
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

impl<T> Read for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            MaybeHttpsStream::Http(inner) => Pin::new(&mut TokioIo::new(inner)).poll_read(cx, buf),
            MaybeHttpsStream::Https(inner) => Pin::new(&mut TokioIo::new(inner)).poll_read(cx, buf),
        }
    }
}

impl<T> Write for MaybeHttpsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeHttpsStream::Http(inner) => {
                Pin::new(&mut TokioIo::new(inner)).poll_write(ctx, buf)
            }
            MaybeHttpsStream::Https(inner) => {
                Pin::new(&mut TokioIo::new(inner)).poll_write(ctx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(inner) => Pin::new(&mut TokioIo::new(inner)).poll_flush(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(&mut TokioIo::new(inner)).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeHttpsStream::Http(inner) => Pin::new(&mut TokioIo::new(inner)).poll_shutdown(ctx),
            MaybeHttpsStream::Https(inner) => Pin::new(&mut TokioIo::new(inner)).poll_shutdown(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_session_cache_capacity, HttpTarget};
    use crate::HttpsLayerSettings;

    #[test]
    fn zero_session_cache_capacity_preserves_legacy_behavior() {
        let mut settings = HttpsLayerSettings::builder();
        settings.set_session_cache_capacity(0);

        assert_eq!(effective_session_cache_capacity(&settings.build()), 1);
    }

    #[test]
    fn missing_host_error_is_preserved() {
        let error = HttpTarget::try_new("/missing-host".parse().unwrap())
            .err()
            .expect("missing host should fail");

        assert_eq!(error, "URI missing host");
    }
}
