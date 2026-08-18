//! TLS setup.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};

/// Build the shared rustls config for every feed connection.
///
/// The crypto provider is passed explicitly rather than read from rustls'
/// process-global slot, so embedding this crate can never fight with whatever
/// the host application installed.
pub(crate) fn client_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            Error::Config(format!(
                "the TLS provider supports none of the required protocol versions: {e}"
            ))
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();

    // A websocket upgrade is an HTTP/1.1 mechanism. Offering `h2` invites a
    // front end to negotiate it and then reject the upgrade.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Reconnects happen off the read path, but resuming in one round trip
    // narrows the window in which messages are being missed.
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(8);

    Ok(Arc::new(cfg))
}
