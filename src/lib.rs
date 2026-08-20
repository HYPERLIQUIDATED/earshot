//! A subscriber for the Robinhood chain sequencer feed.
//!
//! The sequencer broadcasts every message it orders over a websocket relay at
//! `wss://feed.mainnet.chain.robinhood.com/feed`, in Arbitrum Nitro's standard
//! feed format. The broadcast happens at the moment of ordering, before the
//! block is executed, which is why reading it directly is the earliest a
//! transaction can be seen off-chain.
//!
//! The margin that buys is tens of milliseconds, not more. Measured from
//! inside the relay's region against `eth_subscribe("newHeads")` on a public
//! websocket RPC, matched on block hash, the feed delivers a block about
//! **15ms** before the header arrives and about **35ms** before a subscriber
//! that then fetches the bodies has the transactions in hand. The second
//! figure is the one to hold on to: roughly a third of a block time, bought
//! by skipping execution and the round trip for the block body.
//!
//! A subscription is the baseline to measure against. Polling
//! `eth_getBlockByNumber("latest")` puts the feed 500ms ahead at the median,
//! but that gap is mostly the cost of discovering a block by asking
//! repeatedly rather than the node knowing it late — and `latest` advances in
//! jumps, so a 50ms poller observes only 19% of blocks at all.
//!
//! # What arrives
//!
//! Each frame is JSON wrapping a base64 payload, and that payload has three
//! layers worth knowing about:
//!
//! 1. A **broadcast message** with the sequence number, the inbox header the
//!    sequencer stamped, and the hash of the block this will become.
//! 2. An **L2 message**, almost always a *batch*: a length-prefixed sequence
//!    of nested L2 messages.
//! 3. The leaves, each a **signed transaction** in EIP-2718 form.
//!
//! [`FeedClient`] walks all three and hands back [`FeedMessage`]s with the
//! transactions already decoded, their hashes computed locally.
//!
//! # Reconnecting
//!
//! The relay keeps a backlog and replays it to every new subscriber. How far
//! back varies widely: measured against a connection held open to watch the
//! tip, a fresh one has started anywhere from 560 to 3300 messages behind it,
//! a minute at the low end and five at the high. The spread is not noise —
//! the backlog's start holds still while the tip advances and then jumps
//! forward, the way a segmented buffer drops a whole segment at once, so the
//! reach is a sawtooth and the low end is what to plan against. A reconnect
//! that completes inside it loses nothing; one that takes longer leaves a
//! hole that only an RPC node can fill.
//!
//! What cannot be done is *choosing* where to resume:
//! `Arbitrum-Requested-Sequence-Number` is ignored, and the backlog arrives
//! whether it is wanted or not. That makes deduplication load-bearing rather
//! than a nicety — every reconnect delivers hundreds of messages the caller
//! has already seen, and they are dropped before they reach
//! [`FeedClient::recv`]. What does get through is the hole, if there was one:
//! the first message after it carries a non-zero
//! [`missed_before`](FeedMessage::missed_before).
//!
//! # What the feed does not promise
//!
//! Frames carry a `signatureV2` from the sequencer's key, which this crate
//! does not check. Everything the feed says is a claim until a node confirms
//! it — including the block hash, which is what the sequencer *intends* to
//! produce.
//!
//! Nor does arriving first make the feed *fresh*. The relay can fall behind
//! the chain and then catch up by delivering faster, and while it does, every
//! local signal looks healthy: messages keep their cadence, nothing is
//! skipped, and each one still arrives before the next. Over seven and a half
//! hours in the relay's own region this happened three times, the worst of
//! them 36 seconds behind and cleared by delivering at four times the chain's
//! rate. The one thing that gives it away is
//! [`header.timestamp`](MessageHeader::timestamp) against the local clock —
//! its *minimum* over a rolling window, not the difference itself, which is a
//! sawtooth because the field is seconds and ten blocks share each one. That
//! minimum sits near 0.1s when the relay is keeping up and reads the lag
//! directly when it is not. Anything that trades on being early should watch
//! it.
//!
//! # Design
//!
//! * **Connections are supervised, not owned by the caller.** A dropped socket
//!   is redialled with exponential backoff in the background, so a caller sees
//!   an interruption as a gap in sequence numbers rather than an error. The
//!   supervisor never gives up, which means it never reports failure either:
//!   [`FeedClient::recv`] simply does not yield while every endpoint is down,
//!   exactly as it does not yield while the chain is quiet. Distinguishing the
//!   two is the caller's, from [`FeedClient::stats`] or from `tracing`:
//!
//!   ```no_run
//!   # use std::time::Duration;
//!   # async fn run(feed: &mut earshot::FeedClient) {
//!   match tokio::time::timeout(Duration::from_secs(60), feed.recv()).await {
//!       Ok(Some(message)) => { /* … */ }
//!       Ok(None) => { /* the client is shutting down */ }
//!       Err(_) => {
//!           // Nothing for a minute. `stats()` says whether the endpoints are
//!           // connected and how far each has got.
//!       }
//!   }
//!   # }
//!   ```
//! * **Ordering and deduplication are central.** Messages come out in strict
//!   sequence order with no repeats, no matter how many sockets or relays feed
//!   them, or how often those reconnect into the middle of a replayed backlog.
//!   That is what makes redundancy safe to add: the only cost is bandwidth.
//! * **A gap is given a moment to fill before it is called one.** A message
//!   arriving ahead of the expected sequence number means the endpoint that
//!   sent it is missing what comes between, and another endpoint may still
//!   have it. Confirming the gap on that first evidence would advance past
//!   messages already on their way and discard them on arrival — failing at
//!   exactly what the redundancy is for. So the merge holds the gap open for
//!   [`gap_grace`](ClientBuilder::gap_grace), 250ms by default, and closes it
//!   early the moment another endpoint fills it. A contiguous stream is never
//!   held, so this costs latency only where there was already a hole.
//! * **Redundancy is the main latency lever, at every percentile.** Sockets
//!   stall independently and none is reliably the fast one: racing several to
//!   one relay, each wins some share of the messages and none takes most of
//!   them. Racing them takes the first of each message, and every socket added
//!   roughly halves what remains. Measured over 2385 messages against the best
//!   six sockets together could do:
//!
//!   | sockets | median | 90th | 99th |
//!   |---------|--------|------|------|
//!   | 1       | 13.9ms | 108ms | 345ms |
//!   | 2       | 6.0ms  | 46ms  | 174ms |
//!   | 3       | 2.7ms  | 27ms  | 107ms |
//!   | 4       | 1.1ms  | 15ms  | 64ms  |
//!
//!   The median matters here as much as the tail. This chain sequences first
//!   come, first served with no priority fee, so a few milliseconds earlier is
//!   a few milliseconds of head start that cannot be bought back — and the
//!   8ms between one socket and two is nearly a quarter of the whole margin
//!   this crate has over a subscription. Those figures are a floor: six
//!   sockets to one relay still share whatever that relay does, where
//!   [`endpoints`](ClientBuilder::endpoints) races independent relays and is
//!   the only defence against one of them falling behind.
//!   [`Endpoint::connections`] multiplies sockets within one.
//! * **The losers are measured, not discarded.** A copy that arrives after the
//!   race is decided says how far behind its relay was.
//!   [`FeedClient::stats`] reports that distribution per endpoint, which is
//!   both what tells you a relay is drifting while it still appears healthy
//!   and what says, after the fact, how much the redundancy was worth.
//! * **No compression is negotiated.** The handshake offers no websocket
//!   extensions, so frames arrive uncompressed and the read path has nothing
//!   to inflate.
//! * **Backpressure is real.** The buffer absorbs bursts; a consumer that
//!   stays behind stalls the socket instead of quietly dropping messages.
//! * **Parsing is strict, but a bad message is not fatal.** Non-canonical RLP
//!   is rejected, because accepting it would produce a transaction whose hash
//!   is not its hash. A payload that fails anyway is still delivered, with
//!   whatever decoded, the failure in
//!   [`parse_error`](FeedMessage::parse_error), and the raw bytes intact.
//!
//! # Example
//!
//! ```no_run
//! use earshot::FeedClient;
//!
//! # async fn run() -> Result<(), earshot::Error> {
//! let mut feed = FeedClient::connect().await?;
//!
//! while let Some(message) = feed.recv().await {
//!     for tx in &message.transactions {
//!         println!(
//!             "{} -> {:?} value {} ({} bytes of input)",
//!             tx.hash,
//!             tx.to,
//!             tx.value,
//!             tx.input.len(),
//!         );
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Senders
//!
//! A transaction carries no sender, only a signature that a secp256k1
//! recovery turns into one. Enable the `recover` feature for
//! [`Transaction::recover_sender`]:
//!
//! ```toml
//! earshot = { version = "0.1", features = ["recover"] }
//! ```
//!
//! ```
//! # #[cfg(feature = "recover")]
//! # fn demo(tx: &earshot::Transaction) {
//! if let Some(from) = tx.recover_sender() {
//!     println!("{from} sent {}", tx.hash);
//! }
//! # }
//! ```
//!
//! It is off by default because it pulls in libsecp256k1, which needs a C
//! compiler, and because most consumers filter on
//! [`to`](Transaction::to) or [`selector`](Transaction::selector) long before
//! they care who sent anything. Without it the crate still hands over
//! [`signing_hash`](Transaction::signing_hash) and
//! [`signature`](Transaction::signature), which is everything any `ecrecover`
//! needs.

mod client;
mod config;
mod conn;
mod endpoint;
mod error;
mod feed;
#[cfg(feature = "recover")]
mod recover;
mod rlp;
mod tls;
mod tx;
mod types;
mod wire;

pub use client::{ClientBuilder, FeedClient};
pub use config::{MAINNET_CHAIN_ID, MAINNET_FEED_URL, TESTNET_CHAIN_ID, TESTNET_FEED_URL};
pub use endpoint::{Endpoint, EndpointStats, Lateness};
pub use error::{Error, ParseError, Result};
pub use feed::{FeedMessage, L2MessageKind, MessageHeader, MessageKind};
pub use rlp::RlpError;
pub use tx::{AccessListItem, Authorization, Signature, Transaction, TxError, TxType};
pub use types::{Address, B256, Bytes, U256};
