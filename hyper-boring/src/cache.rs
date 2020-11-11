use boring::ssl::SslVersion;
use boring::ssl::{SslSession, SslSessionRef};
use linked_hash_set::LinkedHashSet;
use std::borrow::Borrow;
use std::collections::hash_map::{Entry, HashMap};
use std::hash::{Hash, Hasher};

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionKey {
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
struct HashSession(SslSession);

impl PartialEq for HashSession {
    fn eq(&self, other: &HashSession) -> bool {
        self.0.id() == other.0.id()
    }
}

impl Eq for HashSession {}

impl Hash for HashSession {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.id().hash(state);
    }
}

impl Borrow<[u8]> for HashSession {
    fn borrow(&self) -> &[u8] {
        self.0.id()
    }
}

pub struct SessionCache {
    sessions: HashMap<SessionKey, LinkedHashSet<HashSession>>,
    reverse: HashMap<HashSession, SessionKey>,
}

impl SessionCache {
    pub fn new() -> SessionCache {
        SessionCache {
            sessions: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: SessionKey, session: SslSession) {
        let session = HashSession(session);

        self.sessions
            .entry(key.clone())
            .or_insert_with(LinkedHashSet::new)
            .insert(session.clone());
        self.reverse.insert(session, key);
    }

    pub fn get(&mut self, key: &SessionKey) -> Option<SslSession> {
        let session = {
            let sessions = self.sessions.get_mut(key)?;
            sessions.front().cloned()?.0
        };

        // https://tools.ietf.org/html/rfc8446#appendix-C.4
        // OpenSSL will remove the session from its cache after the handshake completes anyway, but this ensures
        // that concurrent handshakes don't end up with the same session.
        if session.protocol_version() == SslVersion::TLS1_3 {
            self.remove(&session);
        }

        Some(session)
    }

    pub fn remove(&mut self, session: &SslSessionRef) {
        let key = match self.reverse.remove(session.id()) {
            Some(key) => key,
            None => return,
        };

        if let Entry::Occupied(mut sessions) = self.sessions.entry(key) {
            sessions.get_mut().remove(session.id());
            if sessions.get().is_empty() {
                sessions.remove();
            }
        }
    }
}
