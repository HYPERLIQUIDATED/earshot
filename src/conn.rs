//! One websocket connection to the relay, kept up.

use std::sync::Arc;
use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, ClientRequestBuilder, Error as WsError, Message};

use crate::config::{Config, FEED_CLIENT_VERSION, Target};
use crate::endpoint::EndpointState;
use crate::error::{Error, Result};
use crate::feed::FeedMessage;

type Socket = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Why an attempt at staying connected ended.
enum Ended {
    /// A connection that had been established went away: the peer closed, the
    /// socket broke, or nothing arrived in time.
    Dropped(String),
    /// A connection was never established.
    Failed(String),
    /// The client is going away and nothing should be retried.
    Shutdown,
}

/// Keep one connection to the feed up for as long as anyone is listening.
pub(crate) async fn run(
    id: usize,
    endpoint: Arc<EndpointState>,
    cfg: Arc<Config>,
    tls: Arc<ClientConfig>,
    tx: mpsc::Sender<(Arc<EndpointState>, FeedMessage)>,
    mut shutdown: watch::Receiver<bool>,
    mut ready: Option<mpsc::Sender<Result<()>>>,
) {
    let mut backoff = cfg.reconnect_min;

    loop {
        // Dialling is bounded and interruptible. Every step of it — DNS, TCP,
        // TLS, the upgrade — can block on a peer that has accepted the
        // connection and then gone quiet, and an attempt still in flight holds
        // the readiness channel open, which would leave `connect` waiting on a
        // client that is never going to come up.
        let dialled = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            result = timeout(cfg.connect_timeout, connect(&endpoint.url, &cfg, &tls)) => result,
        };

        let outcome = match dialled {
            Ok(Ok(socket)) => {
                tracing::debug!(connection = id, url = %endpoint.url, "feed connected");
                endpoint.connected();
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Ok(())).await;
                }
                backoff = cfg.reconnect_min;
                pump(socket, &endpoint, &cfg, &tx, &mut shutdown).await
            }
            Ok(Err(e)) => {
                let message = e.to_string();
                // A refusal is not a blip. Climbing the backoff from its floor
                // would spend several attempts on an endpoint that has already
                // answered, so start at the ceiling.
                if matches!(e, Error::Rejected { .. }) {
                    backoff = cfg.reconnect_max;
                }
                // The first attempt on every endpoint is reported, so a caller
                // learns about a typo or a dead route instead of waiting on a
                // client that will never yield.
                if let Some(ready) = ready.take() {
                    let _ = ready.send(Err(e)).await;
                }
                Ended::Failed(message)
            }
            Err(_) => Ended::Failed({
                let message = format!("dialling timed out after {:?}", cfg.connect_timeout);
                if let Some(ready) = ready.take() {
                    let _ = ready
                        .send(Err(Error::Connect {
                            url: endpoint.url.clone(),
                            message: message.clone(),
                        }))
                        .await;
                }
                message
            }),
        };

        let reason = match outcome {
            Ended::Shutdown => return,
            Ended::Dropped(reason) => {
                endpoint.disconnected(&reason);
                reason
            }
            Ended::Failed(reason) => {
                endpoint.failed(&reason);
                reason
            }
        };
        if tx.is_closed() {
            return;
        }
        tracing::warn!(
            connection = id,
            url = %endpoint.url,
            ?backoff,
            "feed connection lost: {reason}"
        );

        // Stagger the connections within an endpoint, so several sockets to
        // one relay do not return at the same instant. Endpoints are not
        // staggered against each other: they are separate hosts, and delaying
        // one would only make the fastest of them come back later.
        let stagger = cfg.reconnect_min * u32::try_from(id).unwrap_or(u32::MAX);
        let delay = (backoff + stagger).min(cfg.reconnect_max);
        tokio::select! {
            _ = shutdown.changed() => return,
            () = sleep(delay) => {}
        }
        backoff = (backoff * 2).min(cfg.reconnect_max);
    }
}

/// Dial the relay: TCP, TLS, then the websocket upgrade.
async fn connect(url: &str, cfg: &Config, tls: &Arc<ClientConfig>) -> Result<Socket> {
    let target = Target::parse(url)?;

    let addrs = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|source| Error::Dns {
            host: target.host.clone(),
            source,
        })?;

    let mut last = None;
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(sock) => {
                stream = Some(sock);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let stream = stream.ok_or_else(|| Error::Connect {
        url: url.to_owned(),
        message: last.map_or_else(
            || "hostname resolved to no addresses".to_owned(),
            |e| e.to_string(),
        ),
    })?;

    // Frames are small and arrive continuously, so waiting to coalesce them
    // adds delay and saves nothing.
    let _ = stream.set_nodelay(true);

    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|_| Error::Url(url.to_owned()))?
        .to_owned();
    let stream = TlsConnector::from(Arc::clone(tls))
        .connect(server_name, stream)
        .await
        .map_err(|e| Error::Connect {
            url: url.to_owned(),
            message: format!("TLS handshake failed: {e}"),
        })?;

    let uri: Uri = url.parse().map_err(|_| Error::Url(url.to_owned()))?;
    let request = ClientRequestBuilder::new(uri)
        .with_header("Arbitrum-Feed-Client-Version", FEED_CLIENT_VERSION);

    let config = WebSocketConfig::default()
        .max_message_size(Some(cfg.max_frame_bytes))
        .max_frame_size(Some(cfg.max_frame_bytes));

    let (socket, _response) =
        tokio_tungstenite::client_async_with_config(request, stream, Some(config))
            .await
            .map_err(|e| match e {
                // A status instead of a 101 means the relay is up and has
                // turned this connection away, which is a different problem
                // from not reaching it at all.
                WsError::Http(response) => Error::Rejected {
                    url: url.to_owned(),
                    status: response.status().as_u16(),
                },
                other => Error::Connect {
                    url: url.to_owned(),
                    message: format!("websocket upgrade failed: {other}"),
                },
            })?;

    Ok(socket)
}

/// Read frames until the connection ends.
async fn pump(
    mut socket: Socket,
    endpoint: &Arc<EndpointState>,
    cfg: &Config,
    tx: &mpsc::Sender<(Arc<EndpointState>, FeedMessage)>,
    shutdown: &mut watch::Receiver<bool>,
) -> Ended {
    let mut ping = interval(cfg.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // `interval` fires immediately; the connection is fresh, so skip that one.
    ping.tick().await;

    // The read budget runs from the last frame, not from the top of the loop.
    // A ping tick restarts the loop, so a budget granted per iteration would
    // be reset by the keepalive itself and could never run out.
    let mut last_frame = Instant::now();

    loop {
        let frame = tokio::select! {
            biased;
            _ = shutdown.changed() => return Ended::Shutdown,
            _ = ping.tick() => {
                // Keeps an intermediary from treating the socket as idle, and
                // surfaces a half-open TCP connection long before the read
                // timeout would.
                if let Err(e) = socket.send(Message::Ping(Bytes::new())).await {
                    return Ended::Dropped(format!("ping failed: {e}"));
                }
                continue;
            }
            frame = timeout(
                cfg.read_timeout.saturating_sub(last_frame.elapsed()),
                socket.next(),
            ) => frame,
        };

        let payload = match frame {
            Err(_) => {
                return Ended::Dropped(format!("nothing received for {:?}", cfg.read_timeout));
            }
            Ok(None) => return Ended::Dropped("relay closed the connection".to_owned()),
            Ok(Some(Err(e))) => return Ended::Dropped(e.to_string()),
            Ok(Some(Ok(message))) => message,
        };

        // Stamp arrival before parsing, so the timestamp measures the network
        // rather than the time spent decoding.
        let received_at = Instant::now();
        last_frame = received_at;
        let bytes = match payload {
            Message::Text(text) => text.as_bytes().to_vec(),
            Message::Binary(bytes) => bytes.to_vec(),
            // Neither carries anything to parse — the codec answers an
            // incoming ping itself, and a pong needs no reply — but both have
            // already renewed the read budget above, which is what keeps a
            // quiet chain from being mistaken for a dead socket.
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => return Ended::Dropped("relay sent a close frame".to_owned()),
        };

        match FeedMessage::parse_frame(&bytes, received_at) {
            Ok(messages) => {
                for message in messages {
                    if tx.send((Arc::clone(endpoint), message)).await.is_err() {
                        return Ended::Shutdown;
                    }
                }
            }
            Err(e) => tracing::warn!("discarding an unreadable broadcast frame: {e}"),
        }
    }
}
