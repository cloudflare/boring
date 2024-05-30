use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use antidote::Mutex;
use boring::{
    error::ErrorStack,
    ssl::{
        ConnectConfiguration, SslConnector, SslConnectorBuilder, SslMethod, SslRef,
        SslSessionCacheMode,
    },
};
use http::uri::{Scheme, Uri};
use hyper::rt::{Read, Write};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioIo};
use tower_layer::Layer;
use tower_service::Service;

use crate::{cache::SessionCache, key_index, Inner, MaybeHttpsStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A layer which wraps services in an `HttpsConnector`.
pub struct HttpsLayer {
    inner: Inner,
}

/// Settings for [`HttpsLayer`]
pub struct HttpsLayerSettings {
    session_cache_capacity: usize,
}

impl HttpsLayerSettings {
    /// Constructs an [`HttpsLayerSettingsBuilder`] for configuring settings
    pub fn builder() -> HttpsLayerSettingsBuilder {
        HttpsLayerSettingsBuilder(HttpsLayerSettings::default())
    }
}

impl Default for HttpsLayerSettings {
    fn default() -> Self {
        Self {
            session_cache_capacity: 8,
        }
    }
}

/// Builder for [`HttpsLayerSettings`]
pub struct HttpsLayerSettingsBuilder(HttpsLayerSettings);

impl HttpsLayerSettingsBuilder {
    /// Sets maximum number of sessions to cache. Session capacity is per session key (domain).
    /// Defaults to 8.
    pub fn set_session_cache_capacity(&mut self, capacity: usize) {
        self.0.session_cache_capacity = capacity;
    }

    /// Consumes the builder, returning a new [`HttpsLayerSettings`]
    pub fn build(self) -> HttpsLayerSettings {
        self.0
    }
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
        Self::with_connector_and_settings(ssl, Default::default())
    }

    /// Creates a new `HttpsLayer` with settings
    pub fn with_connector_and_settings(
        mut ssl: SslConnectorBuilder,
        settings: HttpsLayerSettings,
    ) -> Result<HttpsLayer, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::with_capacity(
            settings.session_cache_capacity,
        )));

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);

        ssl.set_new_session_callback({
            let cache = cache.clone();
            move |ssl, session| {
                if let Some(key) = key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        Ok(HttpsLayer {
            inner: Inner {
                ssl: ssl.build(),
                cache,
                callback: None,
                ssl_callback: None,
            },
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
        self.inner.callback = Some(Arc::new(callback));
    }

    /// Registers a callback which can customize the `Ssl` of each connection.
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.ssl_callback = Some(Arc::new(callback));
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

impl<S> HttpsConnector<S>
where
    S: Service<Uri>,
    S::Response: Read + Write + Send + Unpin,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
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
        self.inner.callback = Some(Arc::new(callback));
    }

    /// Registers a callback which can customize the `Ssl` of each connection.
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + 'static + Sync + Send,
    {
        self.inner.ssl_callback = Some(Arc::new(callback));
    }
}

impl<S> Service<Uri> for HttpsConnector<S>
where
    S: Service<Uri>,
    S::Response: Read + Write + Send + Unpin + fmt::Debug + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
{
    type Response = MaybeHttpsStream<S::Response>;
    type Error = BoxError;
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

        let connecting = self.http.call(uri);

        let f = async {
            let conn = connecting.await.map_err(Into::into)?;

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
                    if host[1..last].parse::<std::net::Ipv6Addr>().is_ok() {
                        host = &host[1..last];
                    }
                }
            }

            let ssl = inner.setup_ssl(&uri, host)?;
            let stream = tokio_boring::SslStreamBuilder::new(ssl, TokioIo::new(conn))
                .connect()
                .await?;

            Ok(MaybeHttpsStream::Https(TokioIo::new(stream)))
        };

        Box::pin(f)
    }
}
