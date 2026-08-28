//! Session handshake — validates wallet, chainId, digest, nonce, policyVersion, protocolVersion before TSS begins.

use crate::session::{derive_session_id, SessionBinding, SessionId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    WalletMismatch,
    ChainMismatch,
    DigestMismatch,
    NonceMismatch,
    PolicyVersionMismatch,
    ProtocolVersionMismatch,
    ParticipantSetMismatch,
    ThresholdMismatch,
}

pub fn handshake_validate(
    coordinator_binding: &SessionBinding,
    participant_binding: &SessionBinding,
    expected_participants: &[u8],
    threshold: usize,
) -> Result<SessionId, HandshakeError> {
    if coordinator_binding.wallet != participant_binding.wallet {
        return Err(HandshakeError::WalletMismatch);
    }
    if coordinator_binding.chain_id != participant_binding.chain_id {
        return Err(HandshakeError::ChainMismatch);
    }
    if coordinator_binding.digest != participant_binding.digest {
        return Err(HandshakeError::DigestMismatch);
    }
    if coordinator_binding.nonce != participant_binding.nonce {
        return Err(HandshakeError::NonceMismatch);
    }
    if coordinator_binding.policy_version != participant_binding.policy_version {
        return Err(HandshakeError::PolicyVersionMismatch);
    }
    if coordinator_binding.signing_protocol_version != participant_binding.signing_protocol_version
    {
        return Err(HandshakeError::ProtocolVersionMismatch);
    }
    // Participant set and threshold are validated at provider level; handshake ensures session_id matches
    let sid_coord = derive_session_id(coordinator_binding);
    let sid_part = derive_session_id(participant_binding);
    if sid_coord != sid_part {
        return Err(HandshakeError::DigestMismatch);
    }
    // Threshold check would be done by DKG material; handshake just ensures session_id is consistent
    let _ = (expected_participants, threshold);
    Ok(sid_coord)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(
        wallet: [u8; 20],
        chain: u64,
        nonce: u64,
        digest: [u8; 32],
        policy: u64,
        ver: &str,
        random: [u8; 32],
    ) -> SessionBinding {
        SessionBinding {
            wallet,
            chain_id: chain,
            nonce,
            digest,
            policy_version: policy,
            signing_protocol_version: ver.into(),
            random,
        }
    }
    #[test]
    fn handshake_ok_and_mismatch() {
        let b1 = binding(
            [0x11; 20],
            31337,
            0,
            [0xAA; 32],
            1,
            "synedrion/0.3-cggmp24",
            [0x01; 32],
        );
        let b2 = b1.clone();
        assert!(handshake_validate(&b1, &b2, &[0, 1], 2).is_ok());
        let mut b3 = b1.clone();
        b3.digest = [0xBB; 32];
        assert_eq!(
            handshake_validate(&b1, &b3, &[0, 1], 2).unwrap_err(),
            HandshakeError::DigestMismatch
        );
        let mut b4 = b1.clone();
        b4.chain_id = 1;
        assert_eq!(
            handshake_validate(&b1, &b4, &[0, 1], 2).unwrap_err(),
            HandshakeError::ChainMismatch
        );
    }
}
