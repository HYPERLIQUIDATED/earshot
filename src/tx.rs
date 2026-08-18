//! Decoding the transactions the feed carries.
//!
//! Everything the sequencer broadcasts as an [`L2MessageKind::SignedTx`] is an
//! EIP-2718 envelope: a legacy RLP list, or a type byte followed by one. This
//! module turns those bytes into fields, and computes both the transaction
//! hash and the hash that was signed.
//!
//! [`L2MessageKind::SignedTx`]: crate::L2MessageKind::SignedTx

use tiny_keccak::{Hasher, Keccak};

use crate::rlp::{Rlp, RlpError, encode_list_header, encode_u64};
use crate::types::{Address, B256, Bytes, U256};

/// Which EIP-2718 envelope a transaction uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxType {
    /// Pre-EIP-2718 transaction, with an optional EIP-155 chain id in `v`.
    Legacy,
    /// EIP-2930, type `0x01`: legacy pricing plus an access list.
    AccessList,
    /// EIP-1559, type `0x02`: base fee plus priority fee.
    DynamicFee,
    /// EIP-7702, type `0x04`: sets code on an EOA.
    SetCode,
}

impl TxType {
    /// The EIP-2718 type byte, `0x00` for legacy.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Legacy => 0x00,
            Self::AccessList => 0x01,
            Self::DynamicFee => 0x02,
            Self::SetCode => 0x04,
        }
    }
}

/// A secp256k1 signature, as carried by the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature {
    /// Parity of the recovered public key's y coordinate: the recovery id.
    pub y_parity: bool,
    /// The `r` component.
    pub r: U256,
    /// The `s` component.
    pub s: U256,
}

/// One `(address, storage keys)` entry of an EIP-2930 access list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessListItem {
    /// Account being warmed.
    pub address: Address,
    /// Storage slots of that account being warmed.
    pub storage_keys: Vec<B256>,
}

/// One EIP-7702 authorization tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authorization {
    /// Chain the authorization is valid on; zero means any chain.
    pub chain_id: U256,
    /// Address whose code the authorizing account delegates to.
    pub address: Address,
    /// Nonce the authorizing account must have.
    pub nonce: u64,
    /// Signature by the authorizing account.
    pub signature: Signature,
}

/// A signed transaction, as broadcast by the sequencer.
///
/// The sender is deliberately absent: recovering it costs a secp256k1
/// operation and a dependency this crate does not need to have an opinion
/// about. [`Transaction::signing_hash`] and [`Transaction::signature`] are
/// everything an `ecrecover` needs — see the crate documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// `keccak256` of [`Transaction::raw`]: the hash the chain knows it by.
    pub hash: B256,
    /// Which envelope this transaction uses.
    pub tx_type: TxType,
    /// Chain id. `None` only for a legacy transaction signed before EIP-155.
    pub chain_id: Option<u64>,
    /// Sender's nonce.
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Maximum total price per gas. For [`TxType::Legacy`] and
    /// [`TxType::AccessList`] this is the flat `gasPrice`.
    pub max_fee_per_gas: u128,
    /// Maximum tip per gas. Equal to [`Transaction::max_fee_per_gas`] for the
    /// two types that price gas with a single field.
    pub max_priority_fee_per_gas: u128,
    /// Recipient, or `None` for a contract creation.
    pub to: Option<Address>,
    /// Value moved, in wei.
    pub value: U256,
    /// Call data.
    pub input: Bytes,
    /// EIP-2930 access list; empty for [`TxType::Legacy`].
    pub access_list: Vec<AccessListItem>,
    /// EIP-7702 authorizations; empty for every other type.
    pub authorization_list: Vec<Authorization>,
    /// The signature over [`Transaction::signing_hash`].
    pub signature: Signature,
    /// The 32 bytes the sender actually signed.
    pub signing_hash: B256,
    /// The encoded transaction, exactly as it came off the wire.
    pub raw: Bytes,
}

/// Why a transaction could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// There were no bytes to decode.
    #[error("empty transaction payload")]
    Empty,

    /// The leading byte is neither an RLP list nor a supported type byte.
    #[error("unsupported transaction type 0x{0:02x}")]
    UnsupportedType(u8),

    /// The RLP body was malformed.
    #[error("malformed transaction RLP: {0}")]
    Rlp(#[from] RlpError),

    /// A legacy `v` was neither 27/28 nor a valid EIP-155 value.
    #[error("legacy transaction has an out-of-range v: {0}")]
    BadRecoveryId(u64),

    /// A typed transaction's `yParity` was something other than 0 or 1.
    #[error("yParity must be 0 or 1, got {0}")]
    BadParity(u64),
}

/// `keccak256`.
fn keccak(bytes: &[u8]) -> B256 {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(bytes);
    hasher.finalize(&mut out);
    B256(out)
}

impl Transaction {
    /// Decode one EIP-2718 transaction envelope.
    ///
    /// # Errors
    ///
    /// Returns [`TxError`] if the bytes are not a well-formed, canonically
    /// encoded transaction of a supported type.
    pub fn decode(raw: &[u8]) -> Result<Self, TxError> {
        let first = *raw.first().ok_or(TxError::Empty)?;
        match first {
            // An RLP list header: a legacy transaction.
            0xc0..=0xff => Self::decode_legacy(raw),
            // An EIP-2718 type byte.
            0x00..=0x7f => Self::decode_typed(first, raw),
            _ => Err(TxError::UnsupportedType(first)),
        }
    }

    fn decode_legacy(raw: &[u8]) -> Result<Self, TxError> {
        let mut outer = Rlp::new(raw);
        let mut body = outer.next_list()?;
        outer.finish()?;

        let nonce = body.next_u64()?;
        let gas_price = body.next_u128()?;
        let gas_limit = body.next_u64()?;
        let to = body.next_address_opt()?;
        let value = body.next_u256()?;
        let input = body.next_bytes()?;

        // Where the signature starts is also where the signed payload ends.
        let signed_len = body.consumed();

        let v = body.next_u64()?;
        let signature = Signature {
            y_parity: false,
            r: body.next_u256()?,
            s: body.next_u256()?,
        };
        body.finish()?;

        // Pre-EIP-155 uses 27/28 and signs six fields; EIP-155 folds the chain
        // id into v and signs those six plus `chain_id, 0, 0`.
        let (chain_id, y_parity) = match v {
            27 | 28 => (None, v == 28),
            35.. => (Some((v - 35) / 2), (v - 35) % 2 == 1),
            _ => return Err(TxError::BadRecoveryId(v)),
        };

        let mut tail = Vec::new();
        if let Some(chain_id) = chain_id {
            encode_u64(chain_id, &mut tail);
            tail.push(0x80);
            tail.push(0x80);
        }
        let signed_items = &body.buf()[..signed_len];
        let mut preimage = Vec::with_capacity(signed_items.len() + tail.len() + 9);
        encode_list_header(signed_items.len() + tail.len(), &mut preimage);
        preimage.extend_from_slice(signed_items);
        preimage.extend_from_slice(&tail);

        Ok(Self {
            hash: keccak(raw),
            tx_type: TxType::Legacy,
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            to,
            value,
            input: input.into(),
            access_list: Vec::new(),
            authorization_list: Vec::new(),
            signature: Signature {
                y_parity,
                ..signature
            },
            signing_hash: keccak(&preimage),
            raw: raw.into(),
        })
    }

    fn decode_typed(type_byte: u8, raw: &[u8]) -> Result<Self, TxError> {
        let tx_type = match type_byte {
            0x01 => TxType::AccessList,
            0x02 => TxType::DynamicFee,
            0x04 => TxType::SetCode,
            other => return Err(TxError::UnsupportedType(other)),
        };

        let mut outer = Rlp::new(&raw[1..]);
        let mut body = outer.next_list()?;
        outer.finish()?;

        let chain_id = body.next_u64()?;
        let nonce = body.next_u64()?;
        // 2930 prices gas with one field, the other two with a pair.
        let (max_priority_fee_per_gas, max_fee_per_gas) = if tx_type == TxType::AccessList {
            let gas_price = body.next_u128()?;
            (gas_price, gas_price)
        } else {
            (body.next_u128()?, body.next_u128()?)
        };
        let gas_limit = body.next_u64()?;
        let to = if tx_type == TxType::SetCode {
            // 7702 cannot deploy, so the field is a plain address.
            Some(body.next_address()?)
        } else {
            body.next_address_opt()?
        };
        let value = body.next_u256()?;
        let input = body.next_bytes()?;
        let access_list = decode_access_list(&mut body)?;
        let authorization_list = if tx_type == TxType::SetCode {
            decode_authorization_list(&mut body)?
        } else {
            Vec::new()
        };

        let signed_len = body.consumed();

        let parity = body.next_u64()?;
        if parity > 1 {
            return Err(TxError::BadParity(parity));
        }
        let signature = Signature {
            y_parity: parity == 1,
            r: body.next_u256()?,
            s: body.next_u256()?,
        };
        body.finish()?;

        let signed_items = &body.buf()[..signed_len];
        let mut preimage = Vec::with_capacity(signed_items.len() + 10);
        preimage.push(type_byte);
        encode_list_header(signed_items.len(), &mut preimage);
        preimage.extend_from_slice(signed_items);

        Ok(Self {
            hash: keccak(raw),
            tx_type,
            chain_id: Some(chain_id),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to,
            value,
            input: input.into(),
            access_list,
            authorization_list,
            signature,
            signing_hash: keccak(&preimage),
            raw: raw.into(),
        })
    }

    /// The first four bytes of the call data, if there are that many.
    ///
    /// This is the function selector for a normal contract call, and the
    /// cheapest way to filter a feed down to the calls you care about.
    #[must_use]
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.input.get(..4)?.try_into().ok()
    }
}

fn decode_access_list(rlp: &mut Rlp<'_>) -> Result<Vec<AccessListItem>, RlpError> {
    let mut list = rlp.next_list()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut entry = list.next_list()?;
        let address = entry.next_address()?;
        let mut keys = entry.next_list()?;
        entry.finish()?;

        let mut storage_keys = Vec::new();
        while !keys.is_empty() {
            storage_keys.push(keys.next_b256()?);
        }
        out.push(AccessListItem {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

fn decode_authorization_list(rlp: &mut Rlp<'_>) -> Result<Vec<Authorization>, RlpError> {
    let mut list = rlp.next_list()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let mut entry = list.next_list()?;
        let chain_id = entry.next_u256()?;
        let address = entry.next_address()?;
        let nonce = entry.next_u64()?;
        let y_parity = entry.next_u64()? == 1;
        let r = entry.next_u256()?;
        let s = entry.next_u256()?;
        entry.finish()?;
        out.push(Authorization {
            chain_id,
            address,
            nonce,
            signature: Signature { y_parity, r, s },
        });
    }
    Ok(out)
}
