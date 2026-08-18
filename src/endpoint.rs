//! Per-endpoint state and the statistics read off it.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// One relay to read, and how many connections to open to it.
///
/// Endpoints do not all tolerate the same load: a metered relay may sell a
/// single connection and answer 429 to the second, where a public one is
/// content with three. The count therefore belongs to the endpoint rather
/// than to the client, and this type holds an endpoint's whole configuration,
/// so there is one place to set it and no precedence rule to remember.
///
/// ```no_run
/// # use earshot::{Endpoint, FeedClient};
/// # async fn run() -> Result<(), earshot::Error> {
/// let feed = FeedClient::builder()
///     .endpoints([
///         Endpoint::new("wss://metered.example/feed"),
///         Endpoint::new("wss://public.example/feed").connections(3),
///     ])
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// A bare URL converts into one of these, so
/// [`endpoints`](crate::ClientBuilder::endpoints) also takes a list of
/// strings when nothing needs saying about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    connections: usize,
}

impl Endpoint {
    /// Read this relay over one connection.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            connections: 1,
        }
    }

    /// The Robinhood chain mainnet feed.
    #[must_use]
    pub fn mainnet() -> Self {
        Self::new(crate::MAINNET_FEED_URL)
    }

    /// The Robinhood chain testnet feed.
    #[must_use]
    pub fn testnet() -> Self {
        Self::new(crate::TESTNET_FEED_URL)
    }

    /// Open this many connections to it instead of one.
    ///
    /// Sockets to one relay stall independently, so each additional one adds
    /// a copy of every message and the client takes whichever arrives first.
    /// Measured against six sockets together, each one added roughly halves
    /// the delay that remains, at every percentile — 13.9ms of median with
    /// one, 6.0ms with two, 2.7ms with three.
    ///
    /// How many are worth opening is the caller's to weigh: a socket costs
    /// bandwidth and a connection slot, and relays differ in how many they
    /// allow, a metered one sometimes answering 429 to the second.
    #[must_use]
    pub fn connections(mut self, connections: usize) -> Self {
        self.connections = connections;
        self
    }

    /// The URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// How many connections it will open.
    ///
    /// Named apart from [`connections`](Endpoint::connections) because that
    /// is the setter.
    #[must_use]
    pub const fn connection_count(&self) -> usize {
        self.connections
    }
}

impl<T: Into<String>> From<T> for Endpoint {
    fn from(url: T) -> Self {
        Self::new(url)
    }
}

/// How one feed endpoint is doing.
///
/// A snapshot, taken with [`FeedClient::stats`](crate::FeedClient::stats).
/// Counters are cumulative since the client was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointStats {
    /// The feed URL this endpoint reads.
    pub url: String,
    /// Connections the supervisor last observed as established.
    ///
    /// A connection can break between that observation and the next message,
    /// so this can briefly overstate.
    pub live_conns: usize,
    /// Connections configured for this endpoint.
    pub total_conns: usize,
    /// Messages taken from this endpoint, because it had them first.
    pub delivered: u64,
    /// Messages discarded because they had already been delivered — either
    /// another endpoint got there first, or this one is replaying a backlog
    /// after reconnecting.
    ///
    /// A high count is not waste, it is what redundancy costs. An endpoint
    /// whose `delivered` stays near zero, though, is paying bandwidth for
    /// nothing.
    pub dropped: u64,
    /// The highest sequence number seen from this endpoint.
    ///
    /// The bluntest health check there is, and the one with no caveats: two
    /// endpoints a hundred apart are ten seconds apart, no clock or estimator
    /// involved. It is also the only field that moves when an endpoint stays
    /// connected but stops producing — the counters below simply stop.
    pub last_sequence: Option<u64>,
    /// How far behind the delivered copy this endpoint's late copies arrive.
    ///
    /// Read together with [`delivered`](EndpointStats::delivered), this
    /// answers what reading *only* this endpoint would have cost: a message it
    /// won would have arrived at the same time, and one it lost would have
    /// arrived this much later. That is what the redundancy bought, which is
    /// also why it is a distribution rather than an average — the difference
    /// between one relay and several is a few milliseconds in the middle and
    /// seconds at the far end, and a mean shows neither.
    ///
    /// An endpoint with several connections is timed once per message, on
    /// whichever of its sockets was first, since that is when the endpoint
    /// would have had the message. Its slower sockets are neither its loss nor
    /// its lateness.
    pub lateness: Lateness,
    /// Consecutive connection failures since the last success.
    pub consecutive_failures: u32,
    /// Why the most recent failure happened, cleared by the next success.
    ///
    /// This is the only place the reason is available without a `tracing`
    /// subscriber.
    pub last_failure: Option<String>,
}

/// How far behind the delivered copy an endpoint's late copies arrive.
///
/// Percentiles, not buckets. They are read off a histogram whose resolution
/// is relative rather than absolute — thirty-two steps per doubling — so a
/// figure is within about 3% of the true one at any scale, and reads as a
/// measurement instead of as the nearest rung of a ladder. Keeping every
/// sample would make them exact, at the price of holding millions of them an
/// hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lateness {
    /// Samples behind these figures.
    pub count: u64,
    /// Median.
    pub p50: Option<Duration>,
    /// 90th percentile.
    pub p90: Option<Duration>,
    /// 99th percentile. The one that says what redundancy is worth.
    pub p99: Option<Duration>,
    /// The worst sample seen, exactly.
    pub max: Option<Duration>,
    /// Copies so far behind that they are a backlog being replayed to a
    /// socket that just reconnected, rather than a lost race.
    ///
    /// Kept out of the percentiles deliberately. One reconnect delivers
    /// hundreds of them at once, and letting those in would peg every figure
    /// for the rest of the run. The cut is a threshold and therefore a guess,
    /// so they are counted here rather than discarded.
    pub replays: u64,
}

/// The histogram the figures above are read from.
///
/// Relative resolution, in the manner of `HdrHistogram`: values below
/// [`SUB_COUNT`](Histogram::SUB_COUNT) microseconds get a bucket each, and
/// above that every doubling is divided into the same number of steps. Six
/// decades of range cost a few hundred counters and no allocation.
#[derive(Debug)]
struct Histogram {
    buckets: Box<[AtomicU64]>,
}

impl Histogram {
    /// Steps per doubling, as a power of two.
    const SUB_BITS: u32 = 5;
    /// Steps per doubling. One part in this many is the worst-case error.
    const SUB_COUNT: u64 = 1 << Self::SUB_BITS;
    /// Enough for five seconds, which is where a sample stops being a lost
    /// race and starts being a replayed backlog.
    const BUCKETS: usize = 640;

    fn new() -> Self {
        Self {
            buckets: (0..Self::BUCKETS).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Which bucket a value in microseconds belongs to.
    ///
    /// Below `2 * SUB_COUNT` the index is the value itself; above it, the
    /// leading bits pick a doubling and the next five pick a step within it.
    fn index_of(micros: u64) -> usize {
        if micros < Self::SUB_COUNT * 2 {
            return usize::try_from(micros).unwrap_or(Self::BUCKETS - 1);
        }
        let octave = u64::from(micros.ilog2());
        let shift = octave - u64::from(Self::SUB_BITS);
        let sub = (micros >> shift) - Self::SUB_COUNT;
        let index = Self::SUB_COUNT + (octave - u64::from(Self::SUB_BITS)) * Self::SUB_COUNT + sub;
        usize::try_from(index)
            .unwrap_or(Self::BUCKETS - 1)
            .min(Self::BUCKETS - 1)
    }

    /// The largest value that lands in a bucket, in microseconds.
    fn upper_bound(index: usize) -> u64 {
        let index = index as u64;
        if index < Self::SUB_COUNT * 2 {
            return index;
        }
        let step = (index - Self::SUB_COUNT) / Self::SUB_COUNT;
        let sub = (index - Self::SUB_COUNT) % Self::SUB_COUNT;
        let shift = step;
        ((Self::SUB_COUNT + sub) << shift) + (1 << shift) - 1
    }

    fn record(&self, micros: u64) {
        self.buckets[Self::index_of(micros)].fetch_add(1, Ordering::Relaxed);
    }

    /// Read every counter once, so the figures below agree with each other.
    fn snapshot(&self) -> Vec<u64> {
        self.buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }

    /// The value below which `num/den` of the samples fall, capped at the
    /// largest actually seen.
    fn quantile(
        counts: &[u64],
        total: u64,
        num: u64,
        den: u64,
        max: Option<Duration>,
    ) -> Option<Duration> {
        if total == 0 {
            return None;
        }
        let target = (total * num).div_ceil(den);
        let mut seen = 0;
        for (index, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= target {
                let bound = Duration::from_micros(Self::upper_bound(index));
                return Some(max.map_or(bound, |max| bound.min(max)));
            }
        }
        max
    }
}

/// Marks a value that has never been set.
const UNSET: u64 = u64::MAX;

/// A copy later than this is a replayed backlog, not a lost race.
const REPLAY_THRESHOLD: Duration = Duration::from_secs(5);

/// Live counters for one endpoint, shared between its connections and the
/// task that merges them.
#[derive(Debug)]
pub(crate) struct EndpointState {
    pub(crate) url: String,
    pub(crate) total_conns: usize,
    live: AtomicUsize,
    delivered: AtomicU64,
    dropped: AtomicU64,
    last_sequence: AtomicU64,
    lateness: Histogram,
    /// Microseconds, or [`UNSET`].
    max_lateness: AtomicU64,
    replays: AtomicU64,
    consecutive_failures: AtomicU32,
    last_failure: Mutex<Option<String>>,
    /// Highest sequence number this endpoint has already been timed on, so
    /// its slower sockets are not timed again for the same message.
    last_timed: AtomicU64,
}

impl EndpointState {
    pub(crate) fn new(url: String, total_conns: usize) -> Self {
        Self {
            url,
            total_conns,
            live: AtomicUsize::new(0),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            last_sequence: AtomicU64::new(UNSET),
            lateness: Histogram::new(),
            max_lateness: AtomicU64::new(UNSET),
            replays: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            last_failure: Mutex::new(None),
            last_timed: AtomicU64::new(UNSET),
        }
    }

    pub(crate) fn connected(&self) {
        self.live.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = None;
        }
    }

    pub(crate) fn disconnected(&self, reason: &str) {
        // Saturating, because a connection that never came up never counted.
        let _ = self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
        self.failed(reason);
    }

    pub(crate) fn failed(&self, reason: &str) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut slot) = self.last_failure.lock() {
            *slot = Some(reason.to_owned());
        }
    }

    /// Record a message taken from this endpoint.
    pub(crate) fn took(&self, sequence_number: u64) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        self.saw(sequence_number);
    }

    /// Note the highest sequence number this endpoint has produced, whether
    /// or not the message was used.
    fn saw(&self, sequence_number: u64) {
        let _ = self
            .last_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current == UNSET || sequence_number > current).then_some(sequence_number)
            });
    }

    /// Record a copy that arrived too late to be used.
    ///
    /// Only the merge task calls this, so the read-modify-write below is not
    /// a race.
    pub(crate) fn discarded(&self, sequence_number: u64, lateness: Option<Duration>) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        self.saw(sequence_number);

        let Some(lateness) = lateness else { return };

        // An endpoint running several sockets produces a copy per socket. Its
        // arrival time is the first of them, so the rest say nothing about
        // what reading only this endpoint would have cost — timing them too
        // would weight the distribution towards its slowest socket.
        let previous = self.last_timed.load(Ordering::Relaxed);
        if previous != UNSET && sequence_number <= previous {
            return;
        }
        self.last_timed.store(sequence_number, Ordering::Relaxed);

        if lateness > REPLAY_THRESHOLD {
            self.replays.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let sample = u64::try_from(lateness.as_micros()).unwrap_or(u64::MAX - 1);
        self.lateness.record(sample);

        let current = self.max_lateness.load(Ordering::Relaxed);
        if current == UNSET || sample > current {
            self.max_lateness.store(sample, Ordering::Relaxed);
        }
    }

    pub(crate) fn stats(&self) -> EndpointStats {
        let max = self.max_lateness.load(Ordering::Relaxed);
        EndpointStats {
            url: self.url.clone(),
            live_conns: self.live.load(Ordering::Relaxed),
            total_conns: self.total_conns,
            delivered: self.delivered.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            last_sequence: match self.last_sequence.load(Ordering::Relaxed) {
                UNSET => None,
                seq => Some(seq),
            },
            lateness: {
                let counts = self.lateness.snapshot();
                let total: u64 = counts.iter().sum();
                let max = (max != UNSET).then(|| Duration::from_micros(max));
                let at = |num, den| Histogram::quantile(&counts, total, num, den, max);
                Lateness {
                    count: total,
                    p50: at(1, 2),
                    p90: at(9, 10),
                    p99: at(99, 100),
                    max,
                    replays: self.replays.load(Ordering::Relaxed),
                }
            },
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            last_failure: self.last_failure.lock().ok().and_then(|s| s.clone()),
        }
    }
}
