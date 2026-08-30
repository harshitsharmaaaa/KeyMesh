#![allow(deprecated)]
#![allow(clippy::all)]
//! Phase 2.3 real threshold ECDSA via synedrion 0.3 (CGGMP'24).
//!
//! This crate is isolated from production `KeymeshWallet.execute()`.
//! It provides a `SigningProvider` abstraction backed by synedrion's
//! `KeyInit` + `InteractiveSigning` protocols executed over `manul::TestRuntime`.
//!
//! The prototype `crates/keymesh-tss-proto` remains as the Phase 2.2
//! simulation (Shamir/Lagrange) for comparison.

pub mod dkg;
pub mod envelope;
pub mod errors;
pub mod governance;
pub mod handshake;
pub mod identity;
pub mod lifecycle;
pub mod network;
pub mod participant;
pub mod provider;
pub mod session;
pub mod signing;
pub mod storage;
pub mod tests_lifecycle;
pub mod tests_real;
pub mod transcript;
pub mod transport;

pub use dkg::{GroupPublicKey, ThresholdKeyMaterial};
pub use session::{SessionBinding, SessionId};
pub use signing::{verify_signature, ThresholdSignature};
pub use transcript::SigningTranscript;

use k256::ecdsa::VerifyingKey;

/// Ethereum address derivation: keccak256(uncompressed pubkey[1..])[12..]
pub fn ethereum_address_from_verifying_key(vk: &VerifyingKey) -> [u8; 20] {
    use tiny_keccak::{Hasher, Keccak};
    let point = vk.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    hasher.update(&point.as_bytes()[1..]);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[12..]);
    addr
}
