//! The subscriber: connections, ordering, and the channel out.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::config::{Config, MAINNET_FEED_URL};
use crate::conn;
use crate::endpoint::{Endpoint, EndpointState, EndpointStats};
use crate::error::{Error, Result};
use crate::feed::FeedMessage;
use crate::tls;

/// A live subscription to the sequencer feed.
///
/// Messages come out of [`FeedClient::recv`] in sequencer order, without
/// duplicates, for as long as the client is alive. Connections underneath are
/// re-established as needed, and a caller usually sees nothing of it: a
/// reconnect that lands inside the relay's backlog loses no message and leaves
/// [`FeedMessage::missed_before`] at zero. What it does see is a hole that was
/// too long to cover, as a non-zero value on the first message after it.
///
/// Dropping the client shuts every connection down.
#[derive(Debug)]
pub struct FeedClient {
    rx: mpsc::Receiver<FeedMessage>,
    endpoints: Vec<Arc<EndpointState>>,
    /// Dropped last, which is what tells the background tasks to stop.
    _shutdown: watch::Sender<bool>,
}

/// Configures a [`FeedClient`] before it connects.
#[derive(Debug, Clone, Default)]
pub struct ClientBuilder {
    config: Config,
}

impl FeedClient {
    /// Subscribe to the Robinhood chain mainnet feed with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the first connection cannot be established.
    /// Failures after that are retried in the background.
    pub async fn connect() -> Result<Self> {
        Self::builder().connect().await
    }

    /// Start configuring a client.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Wait for the next message.
    ///
    /// Returns `None` only when every background connection has stopped, which
    /// happens when the client is being dropped.
    pub async fn recv(&mut self) -> Option<FeedMessage> {
        self.rx.recv().await
    }

    /// Take the next message if one is already buffered.
    #[must_use]
    pub fn try_recv(&mut self) -> Option<FeedMessage> {
        self.rx.try_recv().ok()
    }

    /// A snapshot of how each endpoint is doing, in the order configured.
    ///
    /// [`last_sequence`](EndpointStats::last_sequence) compared across
    /// endpoints says which are keeping up,
    /// [`delivered`](EndpointStats::delivered) against
    /// [`dropped`](EndpointStats::dropped) says which are earning their
    /// bandwidth, and [`lateness`](EndpointStats::lateness) says what reading
    /// only one of them would have cost, which is what redundancy is worth.
    #[must_use]
    pub fn stats(&self) -> Vec<EndpointStats> {
        self.endpoints.iter().map(|e| e.stats()).collect()
    }
}

impl ClientBuilder {
    /// Read several relays at once, taking whichever delivers each message
    /// first.
    ///
    /// This is the strongest thing the client can do about latency, and the
    /// only thing it can do about a relay falling behind. Independent relays
    /// stall independently: a message is delivered as soon as the luckiest of
    /// them has it, and one that drops out or drifts is simply outrun rather
    /// than noticed. The merged stream stays ordered and free of duplicates
    /// however many are listed, so the cost is bandwidth and nothing else.
    ///
    /// Takes URLs, or [`Endpoint`]s when they need different connection
    /// counts:
    ///
    /// ```no_run
    /// # use earshot::{Endpoint, FeedClient};
    /// # async fn run() -> Result<(), earshot::Error> {
    /// # let feed =
    /// FeedClient::builder().endpoints(["wss://one.example/feed", "wss://two.example/feed"])
    /// # .connect().await?;
    ///
    /// # let feed =
    /// FeedClient::builder().endpoints([
    ///     Endpoint::new("wss://metered.example/feed"),
    ///     Endpoint::new("wss://public.example/feed").connections(3),
    /// ])
    /// # .connect().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// **Every endpoint must serve the same chain.** Deduplication is by
    /// sequence number and nothing else, so relays for two different chains
    /// do not merge, they collide: the one with larger sequence numbers drives
    /// the high-water mark and the other is discarded wholesale, silently and
    /// with every counter looking healthy. There is no check for this, because
    /// a message carries nothing that identifies its chain — the chain id sits
    /// inside the transactions, and a message need not have any.
    #[must_use]
    pub fn endpoints<I, E>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<Endpoint>,
    {
        self.config.endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// How long a connection may go without receiving anything — including
    /// the relay's own pings — before it is treated as dead. Defaults to 30s.
    #[must_use]
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.config.read_timeout = timeout;
        self
    }

    /// How often to send a websocket ping. Defaults to 15s.
    #[must_use]
    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.config.ping_interval = interval;
        self
    }

    /// The first and longest delays between reconnection attempts.
    /// Defaults to 250ms and 10s.
    #[must_use]
    pub fn reconnect_backoff(mut self, min: Duration, max: Duration) -> Self {
        self.config.reconnect_min = min;
        self.config.reconnect_max = max;
        self
    }

    /// How many messages may sit buffered before the reader stalls the
    /// connections. Defaults to 1024.
    ///
    /// The buffer exists to absorb bursts, not to let a slow consumer fall
    /// arbitrarily behind: once it fills, reads stop and the relay eventually
    /// drops the connection rather than the client silently losing messages.
    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.config.capacity = capacity;
        self
    }

    /// Carry deduplication across a restart, by naming the last sequence
    /// number that was already processed.
    ///
    /// The relay replays a backlog to every new subscriber, so a process that
    /// restarts is handed messages it has already seen and — worse — cannot
    /// tell from [`FeedMessage::missed_before`] whether it also missed
    /// something while it was down, since a fresh client has no previous
    /// message to compare against. Persist the sequence number of the last
    /// message you finished with and pass it back here: the replayed prefix
    /// is dropped as usual, and the first message delivered reports the real
    /// gap across the downtime.
    ///
    /// A value older than the relay's backlog cannot be stitched to, and is
    /// not pretended otherwise: the first message delivered then reports how
    /// far short the replay fell.
    ///
    /// A value *ahead* of the chain suppresses every message until the chain
    /// reaches it, so a stale or foreign one looks like a client that never
    /// delivers. Nothing is logged in that case, because the one line about
    /// suppression is written when delivery begins and delivery never does.
    /// [`FeedClient::stats`] is what shows it: endpoints connected, their
    /// sequence numbers climbing, and every message dropped rather than
    /// delivered.
    #[must_use]
    pub fn resume_after(mut self, sequence_number: u64) -> Self {
        self.config.resume_after = Some(sequence_number);
        self
    }

    /// Largest websocket message to accept. Defaults to 16 MiB.
    #[must_use]
    pub fn max_frame_bytes(mut self, bytes: usize) -> Self {
        self.config.max_frame_bytes = bytes;
        self
    }

    /// Open the connections and start delivering messages.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] or [`Error::Url`] if the settings do not make
    /// sense, and [`Error::Dns`] or [`Error::Connect`] if the first connection
    /// fails. Once that first connection succeeds, later failures are retried
    /// in the background and reported through `tracing` instead.
    pub async fn connect(mut self) -> Result<FeedClient> {
        if self.config.endpoints.is_empty() {
            self.config.endpoints.push(Endpoint::new(MAINNET_FEED_URL));
        }
        self.config.validate()?;
        let config = Arc::new(self.config);
        let tls = tls::client_config()?;

        let endpoints: Vec<Arc<EndpointState>> = config
            .endpoints
            .iter()
            .map(|endpoint| {
                Arc::new(EndpointState::new(
                    endpoint.url().to_owned(),
                    endpoint.connection_count(),
                ))
            })
            .collect();

        let (shutdown, watcher) = watch::channel(false);
        let (raw_tx, raw_rx) = mpsc::channel(config.capacity);
        let (out_tx, out_rx) = mpsc::channel(config.capacity);
        let total: usize = endpoints.iter().map(|e| e.total_conns).sum();
        let (ready_tx, mut ready_rx) = mpsc::channel(total);

        for endpoint in &endpoints {
            for id in 0..endpoint.total_conns {
                tokio::spawn(conn::run(
                    id,
                    Arc::clone(endpoint),
                    Arc::clone(&config),
                    Arc::clone(&tls),
                    raw_tx.clone(),
                    watcher.clone(),
                    Some(ready_tx.clone()),
                ));
            }
        }
        drop(raw_tx);
        drop(ready_tx);

        tokio::spawn(order(raw_rx, out_tx, config.resume_after));

        // One endpoint coming up is enough to start, since the point of
        // listing several is that they fail independently. Only a client where
        // every first attempt failed is reported as a failure to connect,
        // rather than one that quietly never yields a message.
        let mut last = None;
        loop {
            match ready_rx.recv().await {
                Some(Ok(())) => break,
                Some(Err(e)) => last = Some(e),
                None => {
                    return Err(last.unwrap_or_else(|| Error::Connect {
                        url: config
                            .endpoints
                            .iter()
                            .map(Endpoint::url)
                            .collect::<Vec<_>>()
                            .join(", "),
                        message: "the connection tasks stopped before connecting".to_owned(),
                    }));
                }
            }
        }

        Ok(FeedClient {
            rx: out_rx,
            endpoints,
            _shutdown: shutdown,
        })
    }
}

/// Merge every connection into one ordered, duplicate-free stream.
///
/// Each connection delivers in order, so taking only messages past the
/// high-water mark keeps the merged stream ordered as well: a message can
/// only be behind the mark if some other connection already delivered it.
/// The relay's replayed backlog is filtered by exactly the same rule, which
/// is why seeding the mark with `resume_after` extends deduplication across a
/// process restart.
///
/// The copies that lose are not simply discarded. Each one says how far
/// behind its endpoint was, which is the only measurement of a relay drifting
/// that exists before it fails outright.
async fn order(
    mut rx: mpsc::Receiver<(Arc<EndpointState>, FeedMessage)>,
    tx: mpsc::Sender<FeedMessage>,
    resume_after: Option<u64>,
) {
    /// How many recent winners to remember, for timing the losers against.
    /// Covers several minutes at this chain's rate.
    const HISTORY: usize = 4096;

    let mut next_expected = resume_after.map(|last| last.saturating_add(1));
    let mut suppressed = 0u64;
    let mut delivered = false;
    let mut won_at: VecDeque<(u64, Instant, Arc<EndpointState>)> = VecDeque::with_capacity(HISTORY);

    while let Some((endpoint, mut message)) = rx.recv().await {
        if let Some(expected) = next_expected {
            if message.sequence_number < expected {
                suppressed += 1;
                // Contiguous and increasing, so the winner is at a known offset.
                // Only a copy that lost to a *different* endpoint says
                // anything about this one. An endpoint running several
                // sockets produces a copy per socket, and counting its own
                // slower ones as lateness would answer the wrong question:
                // what matters is what reading only this endpoint would have
                // cost, and it cost nothing on a message it won.
                let lateness = won_at.front().and_then(|(first, _, _)| {
                    let offset =
                        usize::try_from(message.sequence_number.checked_sub(*first)?).ok()?;
                    let (_, won, winner) = won_at.get(offset)?;
                    (!Arc::ptr_eq(winner, &endpoint))
                        .then(|| message.received_at.saturating_duration_since(*won))
                });
                endpoint.discarded(message.sequence_number, lateness);
                continue;
            }
            message.missed_before = message.sequence_number - expected;
            if message.missed_before > 0 {
                tracing::warn!(
                    missed = message.missed_before,
                    resumed_at = message.sequence_number,
                    "the feed skipped ahead; the missing messages can only be fetched from an RPC node"
                );
                // The mark jumped, so positions in the history no longer
                // correspond to sequence numbers.
                won_at.clear();
            }
        }
        next_expected = Some(message.sequence_number + 1);

        endpoint.took(message.sequence_number);
        if won_at.len() >= HISTORY {
            won_at.pop_front();
        }
        won_at.push_back((
            message.sequence_number,
            message.received_at,
            Arc::clone(&endpoint),
        ));

        if !delivered {
            delivered = true;
            tracing::debug!(
                suppressed,
                first = message.sequence_number,
                "first delivery; the replayed backlog before this point was dropped"
            );
        }

        if tx.send(message).await.is_err() {
            return;
        }
    }
}
