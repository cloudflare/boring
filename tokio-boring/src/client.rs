//! Reusable client-side TLS connections and session caching.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;
use std::sync::Arc;

use antidote::Mutex;
use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::ssl::{
    self, ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslRef, SslSession,
    SslSessionCacheMode, SslVersion,
};
use linked_hash_set::LinkedHashSet;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{HandshakeError, SslStream, SslStreamBuilder};

const DEFAULT_SESSION_CACHE_CAPACITY: usize = 8;

type ConfigCallback<T> =
    Arc<dyn Fn(&mut ConnectConfiguration, &T) -> Result<(), ErrorStack> + Send + Sync>;
type SslCallback<T> = Arc<dyn Fn(&mut SslRef, &T) -> Result<(), ErrorStack> + Send + Sync>;

/// A borrowed view of the TLS identity and session-cache namespace for a client connection.
///
/// The port is only used to isolate cached sessions for the same peer name on different
/// endpoints. It is not used to establish or route the underlying transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Target<'a> {
    peer_name: &'a str,
    port: u16,
}

impl<'a> Target<'a> {
    /// Creates a client target.
    ///
    /// Square brackets are removed from a valid IPv6 address so it can be used for certificate
    /// verification. Other peer names are preserved unchanged.
    #[must_use]
    pub fn new(peer_name: &'a str, port: u16) -> Self {
        let peer_name = peer_name
            .strip_prefix('[')
            .and_then(|peer_name| peer_name.strip_suffix(']'))
            .filter(|peer_name| peer_name.parse::<Ipv6Addr>().is_ok())
            .unwrap_or(peer_name);

        Self { peer_name, port }
    }

    /// Returns the name used for SNI and certificate verification.
    #[must_use]
    pub fn peer_name(&self) -> &'a str {
        self.peer_name
    }

    /// Returns the port used to isolate cached sessions.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Provides a borrowed [`Target`] view of a richer connection target.
pub trait AsTarget {
    /// Returns the TLS-relevant fields of this target.
    fn as_target(&self) -> Target<'_>;
}

impl AsTarget for Target<'_> {
    fn as_target(&self) -> Target<'_> {
        *self
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct SessionKey<P> {
    peer_name: String,
    port: u16,
    partition: P,
}

impl<P> SessionKey<P> {
    fn new(target: Target<'_>, partition: P) -> Self {
        Self {
            peer_name: target.peer_name.to_owned(),
            port: target.port,
            partition,
        }
    }
}

#[derive(Clone)]
struct HashSession(SslSession);

impl PartialEq for HashSession {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for HashSession {}

impl Hash for HashSession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for HashSession {
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

struct SessionCache<P> {
    sessions: HashMap<SessionKey<P>, LinkedHashSet<HashSession>>,
    per_target_capacity: usize,
}

impl<P> SessionCache<P>
where
    P: Eq + Hash,
{
    fn with_capacity(per_target_capacity: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            per_target_capacity,
        }
    }

    fn insert(&mut self, key: SessionKey<P>, session: SslSession) {
        if self.per_target_capacity == 0 {
            return;
        }

        let session = HashSession(session);
        let sessions = self.sessions.entry(key).or_default();
        if sessions.contains(session.0.id()) {
            return;
        }

        if sessions.len() >= self.per_target_capacity {
            sessions.pop_front();
        }
        sessions.insert(session);
    }

    fn get(&mut self, key: &SessionKey<P>) -> Option<SslSession> {
        let sessions = self.sessions.get_mut(key)?;
        let session = sessions.front()?.clone();

        // RFC 8446 appendix C.4 requires TLS 1.3 tickets to be single-use. Remove the ticket
        // before returning it so concurrent handshakes cannot select the same one.
        if session.0.protocol_version() == SslVersion::TLS1_3 {
            sessions.pop_front();
            if sessions.is_empty() {
                self.sessions.remove(key);
            }
        }

        Some(session.0)
    }
}

/// Performs client-side TLS handshakes over established asynchronous streams.
///
/// Clones share a bounded session cache. The connector does not perform DNS resolution, establish
/// a transport, or interpret application protocols.
pub struct Connector<T, P = ()> {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache<P>>>,
    key_index: Index<Ssl, SessionKey<P>>,
    config_callback: Option<ConfigCallback<T>>,
    ssl_callback: Option<SslCallback<T>>,
}

impl<T, P> Clone for Connector<T, P> {
    fn clone(&self) -> Self {
        Self {
            ssl: self.ssl.clone(),
            cache: Arc::clone(&self.cache),
            key_index: self.key_index,
            config_callback: self.config_callback.clone(),
            ssl_callback: self.ssl_callback.clone(),
        }
    }
}

impl<T, P> Connector<T, P>
where
    T: AsTarget,
    P: Clone + Eq + Hash + Send + Sync + 'static,
{
    /// Creates a connector with a session-cache capacity of eight sessions per target.
    ///
    /// The session-cache mode and new-session callback configured on `ssl` are replaced.
    pub fn new(ssl: SslConnectorBuilder) -> Result<Self, ErrorStack> {
        Self::with_session_cache_capacity(ssl, DEFAULT_SESSION_CACHE_CAPACITY)
    }

    /// Creates a connector with the specified session-cache capacity per target.
    ///
    /// A capacity of zero disables session caching. The session-cache mode and new-session
    /// callback configured on `ssl` are replaced.
    pub fn with_session_cache_capacity(
        mut ssl: SslConnectorBuilder,
        capacity: usize,
    ) -> Result<Self, ErrorStack> {
        let cache = Arc::new(Mutex::new(SessionCache::with_capacity(capacity)));
        let key_index = Ssl::cached_ex_index::<SessionKey<P>>();

        ssl.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        ssl.set_new_session_callback({
            let cache = Arc::clone(&cache);
            move |ssl, session| {
                if let Some(key) = ssl.ex_data(key_index) {
                    cache.lock().insert(key.clone(), session);
                }
            }
        });

        Ok(Self {
            ssl: ssl.build(),
            cache,
            key_index,
            config_callback: None,
            ssl_callback: None,
        })
    }

    /// Registers a callback that customizes each connection configuration.
    ///
    /// The callback runs before session selection and construction of the [`Ssl`] object. Changes
    /// to hostname verification parameters may be overwritten during `Ssl` construction; use
    /// [`Connector::on_ssl`] for those changes instead. Replaces any previously registered
    /// configuration callback on this connector clone.
    pub fn on_config<F>(&mut self, callback: F)
    where
        F: Fn(&mut ConnectConfiguration, &T) -> Result<(), ErrorStack> + Send + Sync + 'static,
    {
        self.config_callback = Some(Arc::new(callback));
    }

    /// Registers a callback that customizes each constructed [`Ssl`] object before its handshake.
    ///
    /// Replaces any previously registered SSL callback on this connector clone.
    pub fn on_ssl<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &T) -> Result<(), ErrorStack> + Send + Sync + 'static,
    {
        self.ssl_callback = Some(Arc::new(callback));
    }

    fn setup_ssl(&self, source: &T, session_partition: P) -> Result<Ssl, ErrorStack> {
        let mut config = self.ssl.configure()?;

        if let Some(callback) = &self.config_callback {
            callback(&mut config, source)?;
        }

        let target = source.as_target();
        let key = SessionKey::new(target, session_partition);
        if let Some(session) = self.cache.lock().get(&key) {
            // SAFETY: sessions in this cache were created by this connector's SSL context and are
            // isolated by the same target used for this connection.
            unsafe {
                config.set_session(&session)?;
            }
        }

        config.set_ex_data(self.key_index, key);
        let mut ssl = config.into_ssl(target.peer_name())?;

        if let Some(callback) = &self.ssl_callback {
            callback(&mut ssl, source)?;
        }

        Ok(ssl)
    }

    /// Performs a partitioned client-side TLS handshake over an established asynchronous stream.
    ///
    /// Sessions are only resumed when both the target and `session_partition` match. The
    /// partition may contain any additional identity that affects TLS setup, such as the client
    /// certificate selected by a callback.
    pub async fn connect_partitioned<S>(
        &self,
        target: &T,
        session_partition: P,
        stream: S,
    ) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = self
            .setup_ssl(target, session_partition)
            .map_err(|error| HandshakeError(ssl::HandshakeError::SetupFailure(error)))?;

        SslStreamBuilder::new(ssl, stream).connect().await
    }
}

impl<T> Connector<T>
where
    T: AsTarget,
{
    /// Performs a client-side TLS handshake over an established asynchronous stream.
    ///
    /// Sessions are isolated by target. Use [`Connector::connect_partitioned`] on a connector
    /// with a partition type when TLS setup differs between connections to the same target.
    pub async fn connect<S>(&self, target: &T, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_partitioned(target, (), stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::{AsTarget, Target};

    #[test]
    fn target_strips_ipv6_brackets() {
        let target = Target::new("[2001:db8::1]", 443);

        assert_eq!(target.peer_name(), "2001:db8::1");
        assert_eq!(target.port(), 443);
    }

    #[test]
    fn target_preserves_non_ipv6_brackets() {
        let target = Target::new("[example.com]", 443);

        assert_eq!(target.peer_name(), "[example.com]");
    }

    #[test]
    fn target_is_its_own_projection() {
        let target = Target::new("example.com", 8443);

        assert_eq!(target.as_target(), target);
    }
}
