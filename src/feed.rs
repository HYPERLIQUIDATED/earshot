//! What a subscriber receives, and how the sequencer's bytes become it.
//!
//! A broadcast frame is JSON wrapping a base64 blob. That blob is an L2
//! message: usually a *batch*, which is a length-prefixed sequence of nested
//! L2 messages, whose leaves are signed transactions in EIP-2718 form. This
//! module walks that structure and hands back [`FeedMessage`]s.

use std::fmt;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::ParseError;
use crate::tx::Transaction;
use crate::types::{Address, B256, Bytes};
use crate::wire;

/// Nested batches deeper than this are treated as malformed. Nitro applies the
/// same limit when it replays them, so anything deeper could never execute.
const MAX_BATCH_DEPTH: usize = 16;

/// The type of an inbox message, from the header the sequencer signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Kind 3: carries L2 transactions. Everything the sequencer produces.
    L2Message,
    /// Kind 6: end-of-block marker.
    EndOfBlock,
    /// Kind 7: an L2 transaction funded by its L1 poster.
    L2FundedByL1,
    /// Kind 8: a rollup event.
    RollupEvent,
    /// Kind 9: a retryable ticket submitted from L1.
    SubmitRetryable,
    /// Kind 10: a batch used only for gas estimation.
    BatchForGasEstimation,
    /// Kind 11: chain initialization.
    Initialize,
    /// Kind 12: an ETH deposit from L1.
    EthDeposit,
    /// Kind 13: a batch posting report.
    BatchPostingReport,
    /// Kind 0xff: explicitly invalid.
    Invalid,
    /// A kind this crate does not know about.
    Other(u8),
}

impl MessageKind {
    /// Classify a header's `kind` byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            3 => Self::L2Message,
            6 => Self::EndOfBlock,
            7 => Self::L2FundedByL1,
            8 => Self::RollupEvent,
            9 => Self::SubmitRetryable,
            10 => Self::BatchForGasEstimation,
            11 => Self::Initialize,
            12 => Self::EthDeposit,
            13 => Self::BatchPostingReport,
            0xff => Self::Invalid,
            other => Self::Other(other),
        }
    }

    /// The byte this kind is encoded as.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::L2Message => 3,
            Self::EndOfBlock => 6,
            Self::L2FundedByL1 => 7,
            Self::RollupEvent => 8,
            Self::SubmitRetryable => 9,
            Self::BatchForGasEstimation => 10,
            Self::Initialize => 11,
            Self::EthDeposit => 12,
            Self::BatchPostingReport => 13,
            Self::Invalid => 0xff,
            Self::Other(byte) => byte,
        }
    }
}

/// The kind byte that leads an L2 message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L2MessageKind {
    /// Kind 0: an unsigned transaction from a known poster.
    UnsignedUserTx,
    /// Kind 1: a contract-initiated transaction.
    ContractTx,
    /// Kind 2: a call that must not change state.
    NonMutatingCall,
    /// Kind 3: a length-prefixed sequence of nested L2 messages.
    Batch,
    /// Kind 4: one signed EIP-2718 transaction. The common case.
    SignedTx,
    /// Kind 6: a deprecated heartbeat.
    Heartbeat,
    /// Kind 7: a signed transaction in compressed form.
    SignedCompressedTx,
    /// A kind this crate does not know about.
    Other(u8),
}

impl L2MessageKind {
    /// Classify the leading byte of an L2 message.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::UnsignedUserTx,
            1 => Self::ContractTx,
            2 => Self::NonMutatingCall,
            3 => Self::Batch,
            4 => Self::SignedTx,
            6 => Self::Heartbeat,
            7 => Self::SignedCompressedTx,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for L2MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsignedUserTx => f.write_str("unsigned user tx"),
            Self::ContractTx => f.write_str("contract tx"),
            Self::NonMutatingCall => f.write_str("non-mutating call"),
            Self::Batch => f.write_str("batch"),
            Self::SignedTx => f.write_str("signed tx"),
            Self::Heartbeat => f.write_str("heartbeat"),
            Self::SignedCompressedTx => f.write_str("signed compressed tx"),
            Self::Other(byte) => write!(f, "unknown kind {byte}"),
        }
    }
}

/// The inbox header the sequencer stamps on every message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// What kind of message this is.
    pub kind: MessageKind,
    /// Who posted it. For sequencer-produced messages this is the well-known
    /// address `0xa4b0...73657175656e636572` — "sequencer" in ASCII.
    pub sender: Address,
    /// The L1 block the sequencer was tracking when it built this message.
    pub l1_block_number: u64,
    /// The sequencer's timestamp, in seconds. This becomes the L2 block's
    /// timestamp, so it is a claim by the sequencer, not a local measurement.
    ///
    /// Comparing it against the local clock is the only way to notice that the
    /// relay has fallen behind the chain — but not by subtracting directly.
    /// The field is seconds, and this chain produces ten blocks in each of
    /// them, so `now - timestamp` is a sawtooth that climbs from roughly 0.1
    /// to 1.1 within every second and says nothing on its own. Take the
    /// **minimum over a rolling window** of a second or two instead: the
    /// block that lands just after a second boundary is unquantised, so the
    /// minimum is the real lag, to about the block spacing. Measured from the
    /// relay's own region it sits near 0.1s.
    ///
    /// Worth watching: the relay fell behind three times in seven and a half
    /// hours, once by 36 seconds, each time catching up by delivering at four
    /// times the chain's rate. Nothing else in the stream shows it. No
    /// sequence number is skipped, no message is late relative to the one
    /// before it, and the cadence looks like a healthy feed throughout.
    pub timestamp: u64,
    /// Request id, set only for messages that originate on L1.
    pub request_id: Option<B256>,
    /// The L1 base fee the sequencer recorded, in wei.
    pub l1_base_fee: u128,
}

/// One sequenced message, parsed.
#[derive(Debug, Clone)]
pub struct FeedMessage {
    /// Position in the sequencer's total order. Strictly increasing across
    /// everything a [`FeedClient`](crate::FeedClient) hands back.
    pub sequence_number: u64,
    /// How many sequence numbers were skipped immediately before this one.
    ///
    /// Zero in steady state, and zero across a reconnect that completes
    /// inside the relay's backlog, whose reach has been seen anywhere from
    /// 560 to 3300 messages. Non-zero when an outage outlasted it, and then
    /// what passed during the outage can only be fetched from an RPC node.
    pub missed_before: u64,
    /// Hash of the L2 block this message produced, as the sequencer computed
    /// it — available here before any node will serve it.
    pub block_hash: Option<B256>,
    /// How many delayed (L1) inbox messages had been consumed at this point.
    pub delayed_messages_read: u64,
    /// The inbox header.
    pub header: MessageHeader,
    /// The raw L2 payload, base64-decoded. Kept so nothing is lost when a
    /// message holds something this crate does not decode.
    pub l2_msg: Bytes,
    /// The signed transactions this message carries, in sequencer order.
    ///
    /// These are the user transactions, which is not quite the block. Nitro
    /// prepends an `ArbitrumInternalTx` (type `0x6a`) to every block to carry
    /// the L1 block number and pricing updates, and that transaction is not
    /// broadcast here. So a node reports exactly one more transaction for the
    /// block than this holds: `block.transactions` is that internal
    /// transaction followed by these, same order and same hashes. There is no
    /// transaction count in [`MessageHeader`] to compare against — the count
    /// only exists once the payload has been walked.
    pub transactions: Vec<Transaction>,
    /// Set when the payload did not fully decode. `transactions` then holds
    /// everything that decoded before the failure.
    pub parse_error: Option<ParseError>,
    /// When the frame carrying this message finished arriving, stamped at the
    /// socket before any parsing.
    pub received_at: Instant,
}

impl FeedMessage {
    /// Parse one raw broadcast frame into the messages it carries.
    ///
    /// A frame usually holds exactly one message. Frames that carry only a
    /// confirmed-sequence-number update yield an empty vector.
    ///
    /// Per-message payload failures do not fail the frame; they land in
    /// [`FeedMessage::parse_error`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Json`] if the frame is not a well-formed
    /// broadcast envelope.
    pub fn parse_frame(frame: &[u8], received_at: Instant) -> Result<Vec<Self>, ParseError> {
        // A broadcast is a JSON object. Serde would otherwise read a sequence
        // as a struct whose fields all fall back to their defaults, turning
        // any JSON array into a frame that simply carried no messages.
        if frame.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(ParseError::Json(
                "a broadcast frame must be a JSON object".to_owned(),
            ));
        }

        let broadcast: wire::BroadcastMessage =
            serde_json::from_slice(frame).map_err(|e| ParseError::Json(e.to_string()))?;

        Ok(broadcast
            .messages
            .unwrap_or_default()
            .into_iter()
            .map(|msg| Self::from_wire(msg, received_at))
            .collect())
    }

    fn from_wire(msg: wire::BroadcastFeedMessage, received_at: Instant) -> Self {
        let header = msg.message.message.header;
        let mut parsed = Parsed::default();

        let l2_msg = msg.message.message.l2_msg.map_or_else(Vec::new, |encoded| {
            BASE64.decode(encoded).unwrap_or_else(|_| {
                parsed.fail(ParseError::Base64);
                Vec::new()
            })
        });

        // Only kind 3 carries the batch/signed-tx structure. Other kinds keep
        // their payload verbatim rather than being forced through a parser
        // that was never meant for them.
        let kind = MessageKind::from_byte(header.kind);
        if kind == MessageKind::L2Message && parsed.error.is_none() && !l2_msg.is_empty() {
            parsed.walk(&l2_msg, 0);
        }

        Self {
            sequence_number: msg.sequence_number,
            missed_before: 0,
            block_hash: msg.block_hash,
            delayed_messages_read: msg.message.delayed_messages_read,
            header: MessageHeader {
                kind,
                sender: header.sender,
                l1_block_number: header.block_number,
                timestamp: header.timestamp,
                request_id: header.request_id,
                l1_base_fee: header.base_fee_l1,
            },
            l2_msg: l2_msg.into(),
            transactions: parsed.transactions,
            parse_error: parsed.error,
            received_at,
        }
    }
}

/// Accumulates transactions while walking a possibly nested L2 message.
#[derive(Default)]
struct Parsed {
    transactions: Vec<Transaction>,
    error: Option<ParseError>,
}

impl Parsed {
    /// Keep the first failure; later ones are almost always consequences.
    fn fail(&mut self, error: ParseError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn walk(&mut self, payload: &[u8], depth: usize) {
        if depth > MAX_BATCH_DEPTH {
            self.fail(ParseError::NestingTooDeep);
            return;
        }
        let Some((&kind, body)) = payload.split_first() else {
            self.fail(ParseError::Empty);
            return;
        };

        match L2MessageKind::from_byte(kind) {
            L2MessageKind::Batch => self.walk_batch(body, depth),
            L2MessageKind::SignedTx => match Transaction::decode(body) {
                Ok(tx) => self.transactions.push(tx),
                Err(e) => self.fail(e.into()),
            },
            // Anything else is left in `l2_msg` for the caller to deal with.
            other => self.fail(ParseError::UnhandledKind(other)),
        }
    }

    /// A batch is `[u64 big-endian length][that many bytes]` repeated.
    fn walk_batch(&mut self, mut rest: &[u8], depth: usize) {
        while !rest.is_empty() {
            let Some((len_bytes, tail)) = rest.split_at_checked(8) else {
                self.fail(ParseError::TruncatedBatch);
                return;
            };
            let len = u64::from_be_bytes(len_bytes.try_into().expect("split_at_checked gave 8"));
            let Ok(len) = usize::try_from(len) else {
                self.fail(ParseError::TruncatedBatch);
                return;
            };
            let Some((entry, tail)) = tail.split_at_checked(len) else {
                self.fail(ParseError::TruncatedBatch);
                return;
            };
            // One bad entry must not cost the caller the rest of the block, so
            // the failure is recorded and the walk continues.
            self.walk(entry, depth + 1);
            rest = tail;
        }
    }
}
