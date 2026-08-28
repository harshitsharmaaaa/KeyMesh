//! KeyMesh Phase 2.2 — Threshold ECDSA Prototype (2-of-3)
//!
//! Isolated prototype crate. NOT production, NOT audited.
//! Uses `k256` + `ecdsa` for secp256k1; DKG is distributed (no trusted dealer
//! in the sense that each participant contributes randomness; the simulator
//! combines contributions centrally but each share is derived from all
//! contributions — see `dkg.rs`). Signing requires `t` shares; a single
//! share cannot produce a valid signature (threshold security). The full
//! private key is never exposed via public API; test-only reconstruction is
//! `#[cfg(test)]` behind `#[doc(hidden)]`.
//!
//! Production will replace this simulation with `synedrion`/`cggmp21`
//! CGGMP21 InteractiveSigning with identifiable abort.

pub mod dkg;
pub mod proto_tests;
pub mod session;
pub mod shamir;
pub mod signature;
pub mod test_vectors;
pub mod transcript;
pub mod transport;

pub use dkg::{GroupPublicKey, ParticipantShare, ThresholdKeyMaterial};
pub use session::{SessionBinding, SessionId, SigningSession};
pub use signature::{verify_signature, ThresholdSignature};
pub use transcript::SigningTranscript;

use k256::ecdsa::VerifyingKey;

/// Cheap Ethereum address derivation: keccak256(uncompressed pubkey[1..])[12..]
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

/// Reconstruct private scalar from shares (Lagrange) — TEST-ONLY, hidden.
/// Normal signing path does NOT call this via public API; the threshold
/// signing simulation reconstructs internally and zeroizes immediately.
/// This function exists only for DKG correctness assertions.
#[cfg(test)]
#[doc(hidden)]
pub fn reconstruct_secret_for_test(shares: &[ParticipantShare]) -> k256::Scalar {
    shamir::lagrange_interpolate_at_zero(shares)
}
