//! Error types.

use crate::feed::L2MessageKind;
use crate::tx::TxError;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong reaching the feed.
///
/// Once a client is running, connection failures are not returned to the
/// caller: the supervisor retries them in the background and reports them
/// through `tracing`. These are the failures that stop a client from starting
/// at all.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration could not be used to build a client.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The feed URL was not a `wss://` URL with a host.
    #[error("invalid feed URL `{0}`")]
    Url(String),

    /// Resolving the feed hostname failed.
    #[error("DNS resolution for `{host}` failed: {source}")]
    Dns {
        /// Hostname that failed to resolve.
        host: String,
        /// Underlying resolver error.
        #[source]
        source: std::io::Error,
    },

    /// The relay answered the upgrade with an HTTP status instead of
    /// accepting it.
    ///
    /// Distinct from [`Error::Connect`] because the relay is reachable and
    /// has refused this particular connection — commonly 429, when more were
    /// opened than the endpoint allows. The supervisor treats it as a lasting
    /// condition rather than a blip and waits its full backoff ceiling before
    /// trying again.
    #[error("the relay at {url} refused the upgrade with HTTP {status}")]
    Rejected {
        /// URL that refused.
        url: String,
        /// Status it answered with.
        status: u16,
    },

    /// TCP, TLS or the websocket upgrade failed.
    #[error("could not open the feed at {url}: {message}")]
    Connect {
        /// URL that was being dialled.
        url: String,
        /// Human-readable cause.
        message: String,
    },
}

/// Why a broadcast message could not be turned into transactions.
///
/// A message that fails to parse is still delivered: the raw payload is on
/// [`FeedMessage::l2_msg`](crate::FeedMessage::l2_msg) and whatever decoded
/// before the failure is in
/// [`FeedMessage::transactions`](crate::FeedMessage::transactions).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The frame was not a well-formed broadcast envelope.
    #[error("malformed broadcast JSON: {0}")]
    Json(String),

    /// `l2Msg` was not valid base64.
    #[error("l2Msg is not valid base64")]
    Base64,

    /// An L2 message had no kind byte.
    #[error("empty L2 message")]
    Empty,

    /// A batch entry claimed a length that runs past the end of the payload.
    #[error("batch entry is truncated")]
    TruncatedBatch,

    /// Batches were nested deeper than the format permits.
    #[error("batch nesting is too deep")]
    NestingTooDeep,

    /// A sub-message kind this crate does not decode.
    #[error("unhandled L2 message kind: {0}")]
    UnhandledKind(L2MessageKind),

    /// A signed transaction did not decode.
    #[error("transaction did not decode: {0}")]
    Tx(#[from] TxError),
}
