//! Hyper SSL support via BoringSSL.
#![warn(missing_docs)]

use std::fmt;
use tokio_boring::SslStream;

mod v1;

pub use self::v1::*;

/// Settings for [`HttpsLayer`]
pub struct HttpsLayerSettings {
    session_cache_capacity: usize,
}

impl HttpsLayerSettings {
    /// Constructs an [`HttpsLayerSettingsBuilder`] for configuring settings
    #[must_use]
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
    #[must_use]
    pub fn build(self) -> HttpsLayerSettings {
        self.0
    }
}

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(SslStream<T>),
}

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}
