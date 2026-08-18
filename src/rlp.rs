//! A minimal, strict RLP reader.
//!
//! Only what decoding a transaction needs: walk a list, pull byte strings and
//! integers out of it, and know where in the buffer you stopped. Encodings
//! that are not canonical — a leading zero in an integer, a short string
//! written in the long form — are rejected rather than accepted quietly,
//! because the sequencer never emits them and accepting them would let a
//! malformed payload decode into a transaction whose hash is not its hash.

use crate::types::{Address, B256, U256};

/// Why an RLP payload could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RlpError {
    /// The buffer ended in the middle of an item.
    #[error("RLP input ended mid-item")]
    Truncated,

    /// The item is validly framed but not in its canonical encoding.
    #[error("RLP item is not canonically encoded")]
    NonCanonical,

    /// A list was found where a byte string was expected.
    #[error("expected an RLP byte string, found a list")]
    ExpectedString,

    /// A byte string was found where a list was expected.
    #[error("expected an RLP list, found a byte string")]
    ExpectedList,

    /// An integer item was wider than the type it was read into.
    #[error("RLP integer is too wide for its field")]
    IntegerTooWide,

    /// A fixed-width field (an address, a hash) had the wrong length.
    #[error("RLP item has the wrong length for a fixed-width field")]
    BadLength,

    /// The list held more items than the transaction layout allows.
    #[error("RLP list has trailing items")]
    TrailingItems,
}

/// A cursor over one RLP payload.
#[derive(Debug, Clone)]
pub(crate) struct Rlp<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Rlp<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The bytes this cursor walks over.
    pub(crate) const fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// How far into [`Self::buf`] the cursor has read.
    pub(crate) const fn consumed(&self) -> usize {
        self.pos
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Error out unless every item has been read.
    pub(crate) const fn finish(&self) -> Result<(), RlpError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(RlpError::TrailingItems)
        }
    }

    /// Read one item, returning whether it was a list and its payload.
    fn next_item(&mut self) -> Result<(bool, &'a [u8]), RlpError> {
        let first = *self.buf.get(self.pos).ok_or(RlpError::Truncated)?;
        self.pos += 1;

        let (is_list, len) = match first {
            // A byte below 0x80 encodes itself; there is no header to skip.
            0x00..=0x7f => return Ok((false, &self.buf[self.pos - 1..self.pos])),
            0x80..=0xb7 => (false, usize::from(first - 0x80)),
            0xb8..=0xbf => (false, self.read_long_len(usize::from(first - 0xb7))?),
            0xc0..=0xf7 => (true, usize::from(first - 0xc0)),
            0xf8..=0xff => (true, self.read_long_len(usize::from(first - 0xf7))?),
        };

        let end = self.pos.checked_add(len).ok_or(RlpError::Truncated)?;
        let payload = self.buf.get(self.pos..end).ok_or(RlpError::Truncated)?;
        self.pos = end;

        // A lone byte below 0x80 must use the one-byte form, not 0x81 0xNN.
        if !is_list && len == 1 && payload[0] < 0x80 {
            return Err(RlpError::NonCanonical);
        }
        Ok((is_list, payload))
    }

    /// Read the length that follows a long-form header byte.
    fn read_long_len(&mut self, len_of_len: usize) -> Result<usize, RlpError> {
        let end = self.pos + len_of_len;
        let bytes = self.buf.get(self.pos..end).ok_or(RlpError::Truncated)?;
        self.pos = end;

        if bytes.first() == Some(&0) {
            return Err(RlpError::NonCanonical);
        }
        let mut len: u64 = 0;
        for &b in bytes {
            len = len
                .checked_shl(8)
                .ok_or(RlpError::NonCanonical)?
                .checked_add(u64::from(b))
                .ok_or(RlpError::NonCanonical)?;
        }
        // Lengths below 56 have a short form and must use it.
        if len < 56 {
            return Err(RlpError::NonCanonical);
        }
        usize::try_from(len).map_err(|_| RlpError::Truncated)
    }

    /// Read a byte string item.
    pub(crate) fn next_bytes(&mut self) -> Result<&'a [u8], RlpError> {
        match self.next_item()? {
            (false, payload) => Ok(payload),
            (true, _) => Err(RlpError::ExpectedString),
        }
    }

    /// Read a list item, returning a cursor over its contents.
    pub(crate) fn next_list(&mut self) -> Result<Self, RlpError> {
        match self.next_item()? {
            (true, payload) => Ok(Self::new(payload)),
            (false, _) => Err(RlpError::ExpectedList),
        }
    }

    /// Read an integer item, rejecting the leading zeros that would make two
    /// encodings of the same number possible.
    fn next_int(&mut self, max_bytes: usize) -> Result<&'a [u8], RlpError> {
        let bytes = self.next_bytes()?;
        if bytes.first() == Some(&0) {
            return Err(RlpError::NonCanonical);
        }
        if bytes.len() > max_bytes {
            return Err(RlpError::IntegerTooWide);
        }
        Ok(bytes)
    }

    pub(crate) fn next_u64(&mut self) -> Result<u64, RlpError> {
        let mut out = [0u8; 8];
        let bytes = self.next_int(8)?;
        out[8 - bytes.len()..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(out))
    }

    pub(crate) fn next_u128(&mut self) -> Result<u128, RlpError> {
        let mut out = [0u8; 16];
        let bytes = self.next_int(16)?;
        out[16 - bytes.len()..].copy_from_slice(bytes);
        Ok(u128::from_be_bytes(out))
    }

    pub(crate) fn next_u256(&mut self) -> Result<U256, RlpError> {
        let bytes = self.next_int(32)?;
        U256::from_be_slice(bytes).ok_or(RlpError::IntegerTooWide)
    }

    /// Read a 32-byte hash.
    pub(crate) fn next_b256(&mut self) -> Result<B256, RlpError> {
        B256::from_slice(self.next_bytes()?).ok_or(RlpError::BadLength)
    }

    /// Read an address, where the empty string means contract creation.
    pub(crate) fn next_address_opt(&mut self) -> Result<Option<Address>, RlpError> {
        let bytes = self.next_bytes()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        Address::from_slice(bytes)
            .map(Some)
            .ok_or(RlpError::BadLength)
    }

    /// Read an address that must be present.
    pub(crate) fn next_address(&mut self) -> Result<Address, RlpError> {
        Address::from_slice(self.next_bytes()?).ok_or(RlpError::BadLength)
    }
}

/// Write the header for a list whose payload is `len` bytes.
pub(crate) fn encode_list_header(len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        // `len` is below 56, so the sum stays inside a byte.
        out.push(0xc0 + u8::try_from(len).expect("len < 56"));
    } else {
        let be = len.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let significant = &be[first..];
        out.push(0xf7 + u8::try_from(significant.len()).expect("at most 8 bytes"));
        out.extend_from_slice(significant);
    }
}

/// Write an integer as a canonical RLP item.
pub(crate) fn encode_u64(value: u64, out: &mut Vec<u8>) {
    if value == 0 {
        out.push(0x80);
        return;
    }
    let be = value.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let significant = &be[first..];
    if significant.len() == 1 && significant[0] < 0x80 {
        out.push(significant[0]);
    } else {
        out.push(0x80 + u8::try_from(significant.len()).expect("at most 8 bytes"));
        out.extend_from_slice(significant);
    }
}
