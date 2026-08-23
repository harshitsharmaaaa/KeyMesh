//! Canonical signed-transaction model (KEYMESH_TX_V1).
//!
//! ## Status: implemented
//!
//! This module is the Rust reference for the wire format defined by the
//! TypeScript protocol package (`packages/protocol/src/canonical.ts`) and
//! enforced on-chain by `contracts/ethereum/src/KeymeshTx.sol`. Shared
//! fixtures in `tests` pin all three implementations to identical canonical
//! bytes and digests; changing the format requires bumping the domain string
//! and regenerating every consumer together.
//!
//! ## Format
//!
//! ```text
//! domain_tag = keccak256("KEYMESH_TX_V1")
//! payload    = domain_tag(32)
//!            | wallet(20) | chain_id(32 BE) | nonce(32 BE)
//!            | to(20)     | value(32 BE)    | data_len(4 BE) | data
//!            | expiry(32 BE, unix seconds)
//! digest     = keccak256(payload)
//! ```
//!
//! Numeric bounds (see `validate`): chain_id/nonce/expiry fit u64, value fits
//! u128. Solidity uses uint256 for all of them; TypeScript uses bigint with
//! identical bounds, so the three implementations agree exactly.

use crate::errors::KeymeshError;
use crate::serialization::Encoder;
use std::sync::OnceLock;
use tiny_keccak::{Hasher, Keccak};

/// Domain separation string; hashed to a 32-byte tag.
pub const DOMAIN: &str = "KEYMESH_TX_V1";

/// Maximum calldata accepted in canonical payloads (mirrors TypeScript).
pub const MAX_DATA_BYTES: usize = 128 * 1024;

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut out = [0u8; 32];
    keccak.update(bytes);
    keccak.finalize(&mut out);
    out
}

/// `keccak256(DOMAIN)`, computed once.
pub fn domain_tag() -> [u8; 32] {
    static TAG: OnceLock<[u8; 32]> = OnceLock::new();
    *TAG.get_or_init(|| keccak256(DOMAIN.as_bytes()))
}

/// A device-authorized transaction bound to one wallet on one chain.
///
/// Signing happens outside this crate: callers hash with [`digest`] and hand
/// the 32-byte digest to their ECDSA provider (see `crypto::CryptoProvider`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymeshTransaction {
    /// 20-byte address of the only wallet allowed to execute this payload.
    pub wallet: [u8; 20],
    pub chain_id: u64,
    /// Wallet-scoped strictly-increasing counter (replay protection).
    pub nonce: u64,
    /// 20-byte destination address.
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    /// Unix seconds; valid while now <= expiry (inclusive boundary).
    pub expiry: u64,
}

impl KeymeshTransaction {
    /// Structural validation independent of wall-clock time.
    pub fn validate(&self) -> Result<(), KeymeshError> {
        if self.chain_id == 0 {
            return Err(KeymeshError::InvalidInput(
                "chain_id must be positive".into(),
            ));
        }
        if self.data.len() > MAX_DATA_BYTES {
            return Err(KeymeshError::InvalidInput(format!(
                "data exceeds {MAX_DATA_BYTES} bytes"
            )));
        }
        Ok(())
    }

    /// Expiry check: valid while `now_seconds <= expiry`.
    pub fn is_valid_at(&self, now_seconds: u64) -> bool {
        now_seconds <= self.expiry
    }

    pub fn validate_at(&self, now_seconds: u64) -> Result<(), KeymeshError> {
        self.validate()?;
        if !self.is_valid_at(now_seconds) {
            return Err(KeymeshError::Expired {
                expiry: self.expiry,
                now: now_seconds,
            });
        }
        Ok(())
    }
}

/// Big-endian uint256 encoding of a u128 (used for value/expiry-style fields).
fn be256_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Big-endian uint256 encoding of a u64.
fn be256_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Canonical KEYMESH_TX_V1 byte encoding. Deterministic and unambiguous:
/// fixed-width fields plus a single length-prefixed dynamic field at the end.
pub fn encode_canonical(tx: &KeymeshTransaction) -> Result<Vec<u8>, KeymeshError> {
    tx.validate()?;
    let mut enc = Encoder::new();
    enc.write_raw(&domain_tag());
    enc.write_raw(&tx.wallet);
    enc.write_raw(&be256_u64(tx.chain_id));
    enc.write_raw(&be256_u64(tx.nonce));
    enc.write_raw(&tx.to);
    enc.write_raw(&be256_u128(tx.value));
    enc.write_bytes(&tx.data); // u32 BE length prefix + raw bytes
    enc.write_raw(&be256_u64(tx.expiry));
    Ok(enc.into_bytes())
}

/// The 32-byte message devices sign: keccak256(canonical bytes).
pub fn digest(tx: &KeymeshTransaction) -> Result<[u8; 32], KeymeshError> {
    Ok(keccak256(&encode_canonical(tx)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::KeymeshError;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 20] {
        let v = hex(s);
        v.try_into().expect("20 bytes")
    }

    /// Shared fixture #1 (eth-transfer); constants must equal packages/protocol/src/vectors.ts.
    fn vector_eth_transfer() -> KeymeshTransaction {
        KeymeshTransaction {
            wallet: hex32("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            chain_id: 31337,
            nonce: 0,
            to: hex32("70997970c51812dc3a010c7d01b50e0d17dc79c8"),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            expiry: 2_000_000_000,
        }
    }

    const VECTOR_ETH_TRANSFER_CANONICAL: &str =
        "908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000000000000007a69000000000000000000000000000000000000000000000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000077359400";
    const VECTOR_ETH_TRANSFER_DIGEST: &str =
        "ef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a";

    #[test]
    fn domain_tag_matches_shared_vector() {
        assert_eq!(
            hex("908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405"),
            domain_tag().to_vec()
        );
    }

    #[test]
    fn canonical_encoding_matches_typescript_vector() {
        let encoded = encode_canonical(&vector_eth_transfer()).unwrap();
        assert_eq!(hex(VECTOR_ETH_TRANSFER_CANONICAL), encoded);
    }

    #[test]
    fn digest_matches_typescript_vector() {
        assert_eq!(
            hex(VECTOR_ETH_TRANSFER_DIGEST),
            digest(&vector_eth_transfer()).unwrap().to_vec()
        );
    }

    #[test]
    fn zero_value_calldata_vector_matches() {
        // Fixture #2 from packages/protocol/src/vectors.ts.
        let tx = KeymeshTransaction {
            wallet: hex32("14dc79964da2c08b23698b3d3cc7ca32193d9955"),
            chain_id: 11155111,
            nonce: 7,
            to: hex32("3c44cdddb6a900fa2b585dd299e03d12fa4293bc"),
            value: 0,
            data: hex("deadbeefcafebabe0123456789abcdef"),
            expiry: 2_000_000_001,
        };
        assert_eq!(
            hex("58f52cacdeacc22a70f0e855c44e50b34348984261d9c6954c48d6f895870b58"),
            digest(&tx).unwrap().to_vec()
        );
    }

    #[test]
    fn mainnet_shaped_vector_matches() {
        // Fixture #3 from packages/protocol/src/vectors.ts.
        let tx = KeymeshTransaction {
            wallet: hex32("23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f"),
            chain_id: 1,
            nonce: 42,
            to: hex32("9965507d1a55bcc2695c58ba16fb37d819b0a4dc"),
            value: 123456789,
            data: [0xaa, 0xbb, 0xcc, 0xdd].repeat(16),
            expiry: 4102444800,
        };
        assert_eq!(
            hex("645dc7006dfac3665699314be7d1a4af4f2a502d9b6099b71af0db0d8f1c0a58"),
            digest(&tx).unwrap().to_vec()
        );
    }

    #[test]
    fn digest_changes_when_any_signed_field_changes() {
        let base = vector_eth_transfer();
        let base_digest = digest(&base).unwrap();

        let mutated = |mutate: &dyn Fn(&mut KeymeshTransaction)| {
            let mut tx = base.clone();
            mutate(&mut tx);
            digest(&tx).unwrap()
        };

        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.nonce = 1)
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.value = 2)
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.chain_id = 31338)
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.data = vec![0x01])
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.expiry = 2_000_000_001)
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.to[0] ^= 0xff)
        );
        assert_ne!(
            base_digest,
            mutated(&|t: &mut KeymeshTransaction| t.wallet[0] ^= 0xff)
        );
    }

    #[test]
    fn validation_rejects_bad_fields() {
        let mut tx = vector_eth_transfer();
        tx.chain_id = 0;
        assert!(matches!(tx.validate(), Err(KeymeshError::InvalidInput(_))));

        let mut tx = vector_eth_transfer();
        tx.data = vec![0u8; MAX_DATA_BYTES + 1];
        assert!(matches!(tx.validate(), Err(KeymeshError::InvalidInput(_))));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let tx = vector_eth_transfer(); // expiry = 2_000_000_000
        assert!(tx.is_valid_at(2_000_000_000), "now == expiry is valid");
        assert!(tx.is_valid_at(1_999_999_999));
        assert!(!tx.is_valid_at(2_000_000_001));

        assert!(tx.validate_at(2_000_000_000).is_ok());
        assert_eq!(
            tx.validate_at(2_000_000_001).unwrap_err(),
            KeymeshError::Expired {
                expiry: 2_000_000_000,
                now: 2_000_000_001,
            }
        );
    }
}
