//! Sender recovery, behind the `recover` feature.

use std::sync::OnceLock;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, VerifyOnly};
use tiny_keccak::{Hasher, Keccak};

use crate::tx::Transaction;
use crate::types::Address;

/// Building a context precomputes tables, so it happens once per process
/// rather than once per recovery.
fn context() -> &'static Secp256k1<VerifyOnly> {
    static CONTEXT: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CONTEXT.get_or_init(Secp256k1::verification_only)
}

impl Transaction {
    /// Recover the address that signed this transaction.
    ///
    /// This is a method and not a field because it is not free: one secp256k1
    /// recovery, tens of microseconds, on every transaction the sequencer
    /// orders. A feed consumer normally narrows on [`to`](Transaction::to) or
    /// [`selector`](Transaction::selector) first and only needs the sender for
    /// the few that survive.
    ///
    /// Returns `None` if the signature does not recover, which means the
    /// transaction could never have been included.
    #[must_use]
    pub fn recover_sender(&self) -> Option<Address> {
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&self.signature.r.to_be_bytes());
        compact[32..].copy_from_slice(&self.signature.s.to_be_bytes());

        let id = RecoveryId::try_from(i32::from(self.signature.y_parity)).ok()?;
        let signature = RecoverableSignature::from_compact(&compact, id).ok()?;
        let key = context()
            .recover_ecdsa(Message::from_digest(self.signing_hash.0), &signature)
            .ok()?;

        // The address is the last 20 bytes of keccak256 over the uncompressed
        // public key, with its leading 0x04 tag stripped.
        let mut hasher = Keccak::v256();
        let mut digest = [0u8; 32];
        hasher.update(&key.serialize_uncompressed()[1..]);
        hasher.finalize(&mut digest);
        Address::from_slice(&digest[12..])
    }
}
