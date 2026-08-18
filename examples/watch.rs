//! Tail the sequencer feed, with every configuration knob spelled out.
//!
//! ```text
//! cargo run --release --example watch
//! cargo run --release --features recover --example watch   # adds the sender column
//! FEED_URL=wss://feed.testnet.chain.robinhood.com/feed cargo run --release --example watch
//! RESUME_AFTER=39987650 cargo run --release --example watch  # continue a previous run
//! ```
//!
//! Every setting below is left at its default value, so this behaves exactly
//! like `FeedClient::connect()`. The point is to show what each one controls.

use std::time::Duration;

use earshot::{Endpoint, FeedClient, MAINNET_FEED_URL};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("FEED_URL").unwrap_or_else(|_| MAINNET_FEED_URL.to_owned());

    let mut builder = FeedClient::builder()
        // Which relays to read, and how many sockets to each. The URL is also
        // the TLS SNI name, so it is what the certificate is validated
        // against.
        //
        // Every socket, to the same relay or a different one, carries an
        // independent copy of every message, and the merged stream takes
        // whichever arrives first; duplicates never reach the caller. Listing
        // more than one relay is also the only defence against one of them
        // falling behind. The count is per endpoint because relays differ in
        // what they allow — a metered one may answer 429 to a second
        // connection where a public one is happy with three.
        .endpoints([Endpoint::new(url).connections(1)])
        // How long a socket may go completely silent before it is declared
        // dead and rebuilt. An incoming ping counts as traffic, and the relay
        // sends them, so this fires on a broken path rather than on a chain
        // that has gone quiet.
        .read_timeout(Duration::from_secs(30))
        // How often to ping the relay. Keeps the front end from reaping an
        // idle socket, and surfaces a half-open TCP connection early.
        .ping_interval(Duration::from_secs(15))
        // Delay before the first reconnect attempt, and the ceiling it doubles
        // towards. Connections within one endpoint are staggered by the first
        // value so they do not all return at the same instant; separate
        // endpoints are not, being separate hosts.
        .reconnect_backoff(Duration::from_millis(250), Duration::from_secs(10))
        // Messages that may sit buffered before reads stall.
        //
        // The buffer absorbs bursts. It deliberately does not let a slow
        // consumer drift: once it fills, the socket stops being read and the
        // relay eventually drops it, which shows up as a reported gap rather
        // than as messages quietly going missing.
        .capacity(1024)
        // Largest websocket message to accept, as a guard against a peer that
        // announces an absurd length.
        .max_frame_bytes(16 * 1024 * 1024);

    // Deduplication across a restart. Unset by default, which is what makes a
    // fresh process take the relay's replayed backlog as new: it has no
    // previous message to compare against, so it also cannot tell whether it
    // missed anything while it was down. Persist the sequence number printed
    // below and hand it back to close that hole.
    if let Ok(resume) = std::env::var("RESUME_AFTER") {
        builder = builder.resume_after(resume.parse()?);
    }

    // Open the connections and wait for the first one to come up. Later
    // failures are retried in the background.
    let mut feed = builder.connect().await?;

    while let Some(message) = feed.recv().await {
        // Non-zero when an outage outlasted the relay's backlog, which is the
        // one thing that has to be backfilled from an RPC node.
        if message.missed_before > 0 {
            println!("--- missed {} message(s) ---", message.missed_before);
        }
        if let Some(error) = &message.parse_error {
            eprintln!("seq {}: {error}", message.sequence_number);
        }

        // The sequence number is also the L2 block number on this chain, and
        // the block holds one transaction more than this: Nitro prepends an
        // internal transaction that is never broadcast.
        println!(
            "seq {} block {} {} tx",
            message.sequence_number,
            message
                .block_hash
                .map_or_else(|| "?".to_owned(), |hash| hash.to_string()),
            message.transactions.len(),
        );

        for tx in &message.transactions {
            let selector = tx
                .selector()
                .map_or_else(|| "        ".to_owned(), const_hex::encode);

            // Built with `--features recover`, the sender is one secp256k1
            // operation away. Without it, `signing_hash` and `signature` are
            // still there for whichever implementation you would rather use.
            #[cfg(feature = "recover")]
            let from = tx.recover_sender().map_or_else(
                || " from ?".to_owned(),
                |address| format!(" from {address}"),
            );
            #[cfg(not(feature = "recover"))]
            let from = "";

            println!(
                "    {} {:?} nonce {} to {} value {} data 0x{selector}{from}",
                tx.hash,
                tx.tx_type,
                tx.nonce,
                tx.to
                    .map_or_else(|| "(create)".to_owned(), |to| to.to_string()),
                tx.value,
            );
        }
    }

    Ok(())
}
