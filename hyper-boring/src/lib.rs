//! Hyper SSL support via OpenSSL.
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use std::sync::Arc;

use antidote::Mutex;
use boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{ConnectConfiguration, Ssl, SslConnector, SslRef},
};
use http::Uri;
use once_cell::sync::OnceCell;

use crate::cache::{SessionCache, SessionKey};

pub use client::{HttpsConnector, HttpsLayer, HttpsLayerSettings, HttpsLayerSettingsBuilder};
pub use stream::MaybeHttpsStream;

mod cache;
mod client;
mod stream;
#[cfg(test)]
mod test;

fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: OnceCell<Index<Ssl, SessionKey>> = OnceCell::new();
    IDX.get_or_try_init(Ssl::new_ex_index).copied()
}

#[derive(Clone)]
struct Inner {
    ssl: SslConnector,
    cache: Arc<Mutex<SessionCache>>,
    callback: Option<Callback>,
    ssl_callback: Option<SslCallback>,
}

type Callback =
    Arc<dyn Fn(&mut ConnectConfiguration, &Uri) -> Result<(), ErrorStack> + Sync + Send>;
type SslCallback = Arc<dyn Fn(&mut SslRef, &Uri) -> Result<(), ErrorStack> + Sync + Send>;

impl Inner {
    fn setup_ssl(&self, uri: &Uri, host: &str) -> Result<Ssl, ErrorStack> {
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

        let mut ssl = conf.into_ssl(host)?;

        if let Some(ref ssl_callback) = self.ssl_callback {
            ssl_callback(&mut ssl, uri)?;
        }

        Ok(ssl)
    }
}
