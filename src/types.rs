//! Small value types used by the parsed output.
//!
//! These exist so the crate can hand back addresses, hashes and 256-bit
//! integers without dragging in a full EVM primitives stack. They are plain
//! byte arrays with the formatting you would expect.

use std::fmt;
use std::ops::Deref;

/// A 20-byte account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub [u8; 20]);

/// A 32-byte hash: a transaction hash, block hash or storage key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct B256(pub [u8; 32]);

/// A 256-bit unsigned integer, stored big-endian.
///
/// Displays as decimal, like every other Ethereum tool; `{:#x}` gives the
/// minimal hex form. Amounts that fit in 128 bits — which is every real value
/// on any chain — can be taken out with [`U256::to_u128`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct U256([u8; 32]);

/// An owned byte string that prints as hex instead of a list of numbers.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Bytes(pub Vec<u8>);

impl Address {
    /// The all-zero address.
    pub const ZERO: Self = Self([0u8; 20]);

    /// Read an address from exactly 20 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }
}

impl B256 {
    /// The all-zero hash.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Read a hash from exactly 32 bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }
}

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Read a big-endian integer from at most 32 bytes, right-aligning it.
    ///
    /// Returns `None` if `bytes` is longer than 32, which in RLP means the
    /// item was not a valid 256-bit integer.
    #[must_use]
    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        Some(Self(out))
    }

    /// The big-endian bytes, zero-padded to 32.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Whether this is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// The value as a `u128`, or `None` if it does not fit.
    #[must_use]
    pub fn to_u128(self) -> Option<u128> {
        if self.0[..16].iter().any(|&b| b != 0) {
            return None;
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&self.0[16..]);
        Some(u128::from_be_bytes(low))
    }

    /// The four 64-bit limbs, most significant first.
    fn limbs(self) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(self.0.chunks_exact(8)) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(buf);
        }
        limbs
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&value.to_be_bytes());
        Self(out)
    }
}

impl Bytes {
    /// The bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

/// Emit `0x`-prefixed lowercase hex for a fixed-size array.
macro_rules! hex_fmt {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", const_hex::encode(self.0))
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", const_hex::encode(self.0))
            }
        }

        impl fmt::LowerHex for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }
                f.write_str(&const_hex::encode(self.0))
            }
        }
    };
}

hex_fmt!(Address);
hex_fmt!(B256);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", const_hex::encode(&self.0))
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", const_hex::encode(&self.0))
    }
}

impl fmt::Display for U256 {
    /// Decimal, by repeated division of the 64-bit limbs by 10^19.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const CHUNK: u128 = 10_000_000_000_000_000_000;

        let mut limbs = self.limbs();
        // Each pass peels off the low 19 decimal digits.
        let mut chunks: Vec<u64> = Vec::with_capacity(4);
        loop {
            let mut rem: u128 = 0;
            let mut nonzero = false;
            for limb in &mut limbs {
                let cur = (rem << 64) | u128::from(*limb);
                *limb = u64::try_from(cur / CHUNK).expect("quotient fits a limb");
                rem = cur % CHUNK;
                nonzero |= *limb != 0;
            }
            chunks.push(u64::try_from(rem).expect("remainder is below 10^19"));
            if !nonzero {
                break;
            }
        }

        write!(f, "{}", chunks.pop().unwrap_or(0))?;
        while let Some(chunk) = chunks.pop() {
            write!(f, "{chunk:019}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::LowerHex for U256 {
    /// Minimal hex, with no leading zeros.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        let first = self.0.iter().position(|&b| b != 0).unwrap_or(31);
        let mut out = const_hex::encode(&self.0[first..]);
        if out.starts_with('0') && out.len() > 1 {
            out.remove(0);
        }
        f.write_str(&out)
    }
}
