//! The subscriber: connections, ordering, and the channel out.

use std::collections::{BTreeMap, VecDeque};
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

    /// How long a gap is held open for another endpoint to fill before it is
    /// reported. Defaults to 250ms.
    ///
    /// A message arriving ahead of the expected sequence number means the
    /// endpoint that sent it is missing what comes between. Another endpoint
    /// may still have it, so the merge waits this long before deciding the
    /// messages are gone, and stops waiting the moment one of them arrives.
    /// Nothing is held while the stream is contiguous, so the cost falls only
    /// where there was already a hole.
    ///
    /// [`Duration::ZERO`] reports a gap on the first evidence of it: the
    /// lowest latency, and the least chance of the redundancy helping.
    #[must_use]
    pub fn gap_grace(mut self, grace: Duration) -> Self {
        self.config.gap_grace = grace;
        self
    }

    /// Budget for opening a connection — name resolution, TCP, TLS and the
    /// websocket upgrade together. Defaults to 10s.
    ///
    /// Each of those can block on a peer that accepts a connection and then
    /// says nothing, and an attempt still in flight is one that
    /// [`connect`](ClientBuilder::connect) may be waiting on.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
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

    /// How many messages may sit buffered at each stage before the reader
    /// stalls the connections. Defaults to 1024.
    ///
    /// The buffer exists to absorb bursts, not to let a slow consumer fall
    /// arbitrarily behind: once it fills, reads stop and the relay eventually
    /// drops the connection rather than the client silently losing messages.
    ///
    /// Three things are bounded by this number — what the connections have
    /// handed the merge, what the merge is holding across an open gap, and
    /// what is waiting to be taken by [`FeedClient::recv`] — so a client can
    /// hold up to three times it. A gap that reaches the bound is confirmed
    /// early rather than held any longer.
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

        tokio::spawn(order(
            raw_rx,
            out_tx,
            config.resume_after,
            config.gap_grace,
            config.capacity,
        ));

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
/// Each connection delivers in order, so a message behind the high-water mark
/// is one some other connection already delivered, and dropping it is what
/// makes the merged stream duplicate-free. The relay's replayed backlog is
/// filtered by the same rule, which is why seeding the mark with
/// `resume_after` extends deduplication across a process restart.
///
/// A message *ahead* of the mark is the interesting case, because it means
/// something between is missing from whichever endpoint sent it — and another
/// endpoint may still have it. Confirming the gap immediately would advance
/// the mark past messages that are on their way, and discard them when they
/// arrive: the one situation redundancy exists for would be the one it failed
/// at. So a gap is held open, and closed early the moment another endpoint
/// fills it. Nothing is held while the stream is contiguous, which is nearly
/// always, so this costs latency only where there was already a hole.
struct Merge {
    /// The next sequence number to go out. `None` until the first message.
    next_expected: Option<u64>,
    /// Messages ahead of the mark, waiting for what comes before them.
    held: BTreeMap<u64, (Arc<EndpointState>, FeedMessage)>,
    /// When the gap stops waiting. On the runtime's clock, since it is a timer.
    deadline: Option<tokio::time::Instant>,
    /// Recent winners, for timing the losing copies against.
    won_at: VecDeque<(u64, Instant, Arc<EndpointState>)>,
    suppressed: u64,
    delivered: bool,
    grace: Duration,
    capacity: usize,
}

impl Merge {
    /// How many recent winners to remember. Covers several minutes at this
    /// chain's rate.
    const HISTORY: usize = 4096;

    fn new(resume_after: Option<u64>, grace: Duration, capacity: usize) -> Self {
        Self {
            next_expected: resume_after.map(|last| last.saturating_add(1)),
            held: BTreeMap::new(),
            deadline: None,
            won_at: VecDeque::with_capacity(Self::HISTORY),
            suppressed: 0,
            delivered: false,
            grace,
            capacity,
        }
    }

    /// Take a copy off a connection.
    ///
    /// Anything behind the mark, or a second copy of something already
    /// waiting, has lost; how late it was is recorded against its endpoint and
    /// it goes no further.
    fn offer(&mut self, endpoint: Arc<EndpointState>, message: FeedMessage) {
        let sequence_number = message.sequence_number;
        let already_held = self.held.contains_key(&sequence_number);

        if self
            .next_expected
            .is_some_and(|expected| sequence_number < expected)
            || already_held
        {
            self.suppressed += 1;
            // Only a copy that lost to a *different* endpoint says anything
            // about this one. An endpoint running several sockets produces a
            // copy per socket, and counting its own slower ones as lateness
            // would answer the wrong question: what matters is what reading
            // only this endpoint would have cost, and it cost nothing on a
            // message it won.
            let against = if already_held {
                self.held
                    .get(&sequence_number)
                    .map(|(winner, first)| (first.received_at, winner))
            } else {
                self.won_at.front().and_then(|(first, _, _)| {
                    let offset = usize::try_from(sequence_number.checked_sub(*first)?).ok()?;
                    let (_, won, winner) = self.won_at.get(offset)?;
                    Some((*won, winner))
                })
            };
            let lateness = against.and_then(|(won, winner)| {
                (!Arc::ptr_eq(winner, &endpoint))
                    .then(|| message.received_at.saturating_duration_since(won))
            });
            endpoint.discarded(sequence_number, lateness);
            return;
        }

        self.held.insert(sequence_number, (endpoint, message));
    }

    /// The next message that can go out, if the one the mark is waiting for
    /// has arrived.
    fn take_ready(&mut self) -> Option<FeedMessage> {
        // The first message ever seen sets the mark rather than being measured
        // against one.
        if self.next_expected.is_none() {
            self.next_expected = self.held.keys().next().copied();
        }
        let expected = self.next_expected?;
        let (endpoint, message) = self.held.remove(&expected)?;
        self.next_expected = Some(expected + 1);

        endpoint.took(expected);
        if self.won_at.len() >= Self::HISTORY {
            self.won_at.pop_front();
        }
        self.won_at
            .push_back((expected, message.received_at, endpoint));

        if !self.delivered {
            self.delivered = true;
            tracing::debug!(
                suppressed = self.suppressed,
                first = expected,
                "first delivery; the replayed backlog before this point was dropped"
            );
        }
        Some(message)
    }

    /// When the open gap stops waiting, arming the timer if it is not yet
    /// running. `None` when there is no gap.
    fn deadline(&mut self) -> Option<tokio::time::Instant> {
        if self.held.is_empty() {
            self.deadline = None;
            return None;
        }
        Some(
            *self
                .deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + self.grace),
        )
    }

    /// Whether the gap has to be closed before taking anything more in.
    ///
    /// Holding a gap open costs memory the incoming channel would otherwise
    /// be refusing to accept, so it is bounded by the same number. Both this
    /// and the deadline are settled before the loop waits on anything, since
    /// a channel with a message ready would otherwise be preferred to a timer
    /// that has already expired, and the bound would not hold.
    fn must_confirm(&mut self) -> bool {
        match self.deadline() {
            None => false,
            Some(at) => self.held.len() >= self.capacity || at <= tokio::time::Instant::now(),
        }
    }

    /// Give up on what is missing and resume from the oldest message held.
    fn confirm_gap(&mut self) {
        self.deadline = None;
        let Some(&resumed) = self.held.keys().next() else {
            return;
        };
        let expected = self.next_expected.unwrap_or(resumed);
        let missed = resumed.saturating_sub(expected);
        if let Some((_, message)) = self.held.get_mut(&resumed) {
            message.missed_before = missed;
        }
        if missed > 0 {
            tracing::warn!(
                missed,
                resumed_at = resumed,
                "the feed skipped ahead; the missing messages can only be fetched from an RPC node"
            );
            // The mark jumped, so positions in the history no longer
            // correspond to sequence numbers.
            self.won_at.clear();
        }
        self.next_expected = Some(resumed);
    }
}

/// Drive the merge: everything ready goes out, then either the gap is closed
/// or the next copy is waited for.
async fn order(
    mut rx: mpsc::Receiver<(Arc<EndpointState>, FeedMessage)>,
    tx: mpsc::Sender<FeedMessage>,
    resume_after: Option<u64>,
    grace: Duration,
    capacity: usize,
) {
    let mut merge = Merge::new(resume_after, grace, capacity);

    loop {
        while let Some(message) = merge.take_ready() {
            if tx.send(message).await.is_err() {
                return;
            }
        }

        if merge.must_confirm() {
            merge.confirm_gap();
            continue;
        }

        let incoming = match merge.deadline() {
            None => rx.recv().await,
            Some(at) => tokio::select! {
                biased;
                incoming = rx.recv() => incoming,
                // The loop head confirms it; coming back through there is what
                // keeps one decision in one place.
                () = tokio::time::sleep_until(at) => continue,
            },
        };

        let Some((endpoint, message)) = incoming else {
            return;
        };
        merge.offer(endpoint, message);
    }
}
