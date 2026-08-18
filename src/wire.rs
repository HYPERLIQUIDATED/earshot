//! The JSON the relay puts on the wire.
//!
//! These mirror Nitro's `BroadcastMessage` tree field for field, including the
//! quirks of Go's JSON encoder: `[]byte` comes out as standard base64,
//! `common.Hash` and `common.Address` as `0x` hex, and `*big.Int` as a bare
//! decimal number. Unknown fields are ignored, so a relay upgrade that adds a
//! field does not take the client down.

use serde::Deserialize;
use serde::de::{self, Deserializer, Unexpected, Visitor};

use crate::types::{Address, B256};

#[derive(Debug, Deserialize)]
pub(crate) struct BroadcastMessage {
    #[serde(default)]
    pub(crate) messages: Option<Vec<BroadcastFeedMessage>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastFeedMessage {
    pub(crate) sequence_number: u64,
    pub(crate) message: MessageWithMetadata,
    #[serde(default, deserialize_with = "de_hash_opt")]
    pub(crate) block_hash: Option<B256>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MessageWithMetadata {
    pub(crate) message: L1IncomingMessage,
    #[serde(default)]
    pub(crate) delayed_messages_read: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct L1IncomingMessage {
    pub(crate) header: Header,
    /// Standard base64; absent on message kinds that carry no L2 payload.
    #[serde(default)]
    pub(crate) l2_msg: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Header {
    pub(crate) kind: u8,
    #[serde(deserialize_with = "de_address")]
    pub(crate) sender: Address,
    pub(crate) block_number: u64,
    pub(crate) timestamp: u64,
    #[serde(default, deserialize_with = "de_hash_opt")]
    pub(crate) request_id: Option<B256>,
    #[serde(default, deserialize_with = "de_u128")]
    pub(crate) base_fee_l1: u128,
}

/// Strip an optional `0x` and decode into a fixed-size array.
fn de_fixed<const N: usize, E: de::Error>(text: &str) -> Result<[u8; N], E> {
    let body = text.strip_prefix("0x").unwrap_or(text);
    let mut out = [0u8; N];
    const_hex::decode_to_slice(body, &mut out)
        .map_err(|_| E::invalid_value(Unexpected::Str(text), &"a hex string of the right width"))?;
    Ok(out)
}

fn de_address<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
    let text = String::deserialize(d)?;
    de_fixed::<20, D::Error>(&text).map(Address)
}

fn de_hash_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<B256>, D::Error> {
    let Some(text) = Option::<String>::deserialize(d)? else {
        return Ok(None);
    };
    de_fixed::<32, D::Error>(&text).map(|bytes| Some(B256(bytes)))
}

/// Read a `*big.Int`, which Go writes as a bare JSON number.
///
/// A string and `null` are accepted too, since the encoding of that type has
/// changed across Nitro versions and nothing here depends on which one arrives.
fn de_u128<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
    struct LenientU128;

    impl Visitor<'_> for LenientU128 {
        type Value = u128;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a non-negative integer")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u128, E> {
            Ok(u128::from(v))
        }

        fn visit_u128<E: de::Error>(self, v: u128) -> Result<u128, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u128, E> {
            u128::try_from(v).map_err(|_| E::invalid_value(Unexpected::Signed(v), &self))
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<u128, E> {
            // serde_json falls back to f64 past u64::MAX. No real base fee
            // gets there, so precision loss below is not reachable in practice.
            if (0.0..3.402_823_669_209_385e38).contains(&v) {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "range-checked directly above"
                )]
                Ok(v as u128)
            } else {
                Err(E::invalid_value(Unexpected::Float(v), &self))
            }
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<u128, E> {
            let body = v.strip_prefix("0x");
            let parsed = match body {
                Some(hex) => u128::from_str_radix(hex, 16),
                None => v.parse(),
            };
            parsed.map_err(|_| E::invalid_value(Unexpected::Str(v), &self))
        }

        fn visit_unit<E: de::Error>(self) -> Result<u128, E> {
            Ok(0)
        }
    }

    d.deserialize_any(LenientU128)
}
