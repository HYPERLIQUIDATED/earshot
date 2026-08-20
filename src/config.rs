//! Endpoints and tunables.

use std::time::Duration;

use crate::endpoint::Endpoint;
use crate::error::{Error, Result};

/// Sequencer feed for the Robinhood chain mainnet.
pub const MAINNET_FEED_URL: &str = "wss://feed.mainnet.chain.robinhood.com/feed";

/// Sequencer feed for the Robinhood chain testnet.
pub const TESTNET_FEED_URL: &str = "wss://feed.testnet.chain.robinhood.com/feed";

/// Chain id of the Robinhood chain mainnet.
pub const MAINNET_CHAIN_ID: u64 = 4663;

/// Chain id of the Robinhood chain testnet.
pub const TESTNET_CHAIN_ID: u64 = 46630;

/// Sent as `Arbitrum-Feed-Client-Version`, matching what Nitro's own feed
/// client reports.
pub(crate) const FEED_CLIENT_VERSION: &str = "2";

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) endpoints: Vec<Endpoint>,
    pub(crate) connect_timeout: Duration,
    pub(crate) gap_grace: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) ping_interval: Duration,
    pub(crate) reconnect_min: Duration,
    pub(crate) reconnect_max: Duration,
    pub(crate) capacity: usize,
    pub(crate) resume_after: Option<u64>,
    pub(crate) max_frame_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Empty stands for the mainnet default, which is filled in when
            // the client connects.
            endpoints: Vec::new(),
            // Covers DNS, TCP, TLS and the upgrade together. A peer that
            // accepts a connection and then says nothing would otherwise hold
            // the attempt open for as long as the kernel allows.
            connect_timeout: Duration::from_secs(10),
            // How long a gap is held open for another endpoint to fill before
            // it is reported. Long enough to cover an endpoint that is merely
            // slow — their lateness runs to about 190ms at the 90th
            // percentile — and short enough that confirming a real gap is not
            // itself a delay worth noticing.
            gap_grace: Duration::from_millis(250),
            // This chain produces about ten blocks a second and the relay
            // pings besides, so half a minute of complete silence means the
            // socket is dead rather than the chain being quiet.
            read_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(15),
            reconnect_min: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(10),
            capacity: 1024,
            resume_after: None,
            max_frame_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.endpoints.is_empty() {
            return Err(Error::Config(
                "at least one endpoint is required".to_owned(),
            ));
        }
        if self.capacity == 0 {
            return Err(Error::Config("capacity must be at least 1".to_owned()));
        }
        // `tokio::time::interval` panics on a zero period, and a zero read
        // budget expires the moment it is granted.
        if self.ping_interval.is_zero() {
            return Err(Error::Config("ping_interval must not be zero".to_owned()));
        }
        if self.read_timeout.is_zero() {
            return Err(Error::Config("read_timeout must not be zero".to_owned()));
        }
        if self.connect_timeout.is_zero() {
            return Err(Error::Config("connect_timeout must not be zero".to_owned()));
        }
        if self.reconnect_min > self.reconnect_max {
            return Err(Error::Config(
                "reconnect_min must not exceed reconnect_max".to_owned(),
            ));
        }
        for endpoint in &self.endpoints {
            if endpoint.connection_count() == 0 {
                return Err(Error::Config(format!(
                    "endpoint `{}` was given zero connections",
                    endpoint.url()
                )));
            }
            Target::parse(endpoint.url())?;
        }
        Ok(())
    }
}

/// Where a feed URL points.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Target {
    /// Pull the host and port out of a `wss://` URL.
    ///
    /// Only `wss` is accepted. Accepting `ws` as well would mean carrying a
    /// second stream type through the connection code for relays that are all
    /// TLS terminated.
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let bad = || Error::Url(url.to_owned());

        let rest = url.strip_prefix("wss://").ok_or_else(bad)?;
        let authority = rest.find(['/', '?', '#']).map_or(rest, |end| &rest[..end]);
        if authority.is_empty() {
            return Err(bad());
        }

        // An IPv6 literal is bracketed, so only look for a port separator
        // after the closing bracket.
        let (host, port) = match authority.strip_prefix('[') {
            Some(after) => {
                let (host, tail) = after.split_once(']').ok_or_else(bad)?;
                (host, tail.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };

        if host.is_empty() {
            return Err(bad());
        }
        let port = match port {
            Some(text) => text.parse().map_err(|_| bad())?,
            None => 443,
        };

        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}
