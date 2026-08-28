//! Signing session — bound to KEYMESH_TX_V1 digest and policy.
//! Mirrors `packages/protocol/src/signing.ts` deriveSessionId logic.

use tiny_keccak::{Hasher, Keccak};

/// Session binding per docs/protocol/tss-signing-protocol.md §2.1
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionBinding {
    pub wallet: [u8; 20],
    pub chain_id: u64,
    pub nonce: u64,
    pub digest: [u8; 32],
    pub policy_version: u64,
    pub signing_protocol_version: String, // e.g. "cggmp21/v1"
    pub random: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn write_u256_be(out: &mut Vec<u8>, v: u64) {
    // Encode as uint256 BE (32 bytes, low 8 bytes carry value)
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&buf);
}

/// Derive sessionId = keccak256(wallet | chainId(32) | nonce(32) | digest(32) | policyVersion(32) | versionBytes | random(32))
/// This matches TS `deriveSessionId` (wallet 20 + 32+32+32+32 + version +32).
pub fn derive_session_id(binding: &SessionBinding) -> SessionId {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&binding.wallet);
    write_u256_be(&mut preimage, binding.chain_id);
    write_u256_be(&mut preimage, binding.nonce);
    preimage.extend_from_slice(&binding.digest);
    write_u256_be(&mut preimage, binding.policy_version);
    preimage.extend_from_slice(binding.signing_protocol_version.as_bytes());
    preimage.extend_from_slice(&binding.random);
    let mut hasher = Keccak::v256();
    hasher.update(&preimage);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    SessionId(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningSessionStatus {
    Started,
    Completed,
    Aborted,
    Failed,
}

#[derive(Clone, Debug)]
pub struct SigningSession {
    pub session_id: SessionId,
    pub binding: SessionBinding,
    pub participants: Vec<u8>, // indices
    pub threshold: usize,
    pub status: SigningSessionStatus,
}

impl SigningSession {
    pub fn new(binding: SessionBinding, participants: Vec<u8>, threshold: usize) -> Self {
        let session_id = derive_session_id(&binding);
        Self {
            session_id,
            binding,
            participants,
            threshold,
            status: SigningSessionStatus::Started,
        }
    }
    /// Monotonic transition — terminal states reject.
    pub fn transition(&mut self, to: SigningSessionStatus) -> Result<(), &'static str> {
        if self.status != SigningSessionStatus::Started {
            return Err("cannot transition from terminal");
        }
        if to == SigningSessionStatus::Started {
            return Err("cannot transition back to Started");
        }
        self.status = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_binding(random_byte: u8) -> SessionBinding {
        SessionBinding {
            wallet: [0x11; 20],
            chain_id: 31337,
            nonce: 0,
            digest: [0xab; 32],
            policy_version: 1,
            signing_protocol_version: "cggmp21/v1".into(),
            random: [random_byte; 32],
        }
    }

    #[test]
    fn session_id_deterministic() {
        let a = derive_session_id(&dummy_binding(0xaa));
        let b = derive_session_id(&dummy_binding(0xaa));
        assert_eq!(a, b);
    }
    #[test]
    fn session_id_changes_with_binding() {
        let base = dummy_binding(0xaa);
        let base_id = derive_session_id(&base);
        let mut with_nonce = base.clone();
        with_nonce.nonce = 1;
        assert_ne!(derive_session_id(&with_nonce), base_id);
    }
    #[test]
    fn session_lifecycle_monotonic() {
        let mut s = SigningSession::new(dummy_binding(0xaa), vec![1, 2], 2);
        assert!(s.transition(SigningSessionStatus::Completed).is_ok());
        assert!(s.transition(SigningSessionStatus::Aborted).is_err());
    }
}
