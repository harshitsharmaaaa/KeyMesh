//! Authenticated TSS message envelope — prevents cross-session, cross-wallet, impersonation, wrong-round.

use k256::ecdsa::Signature;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TssEnvelope {
    pub protocol_version: String, // e.g. "synedrion/0.3-cggmp24"
    pub session_id: [u8; 32],
    pub wallet: [u8; 20],
    pub chain_id: u64,
    pub participant_id: u8,
    pub round: u8,
    pub message_type: String, // "KeyInit", "InteractiveSigning", "Abort" etc.
    pub digest: [u8; 32],     // KEYMESH_TX_V1 digest binding
    pub payload: Vec<u8>,     // opaque TSS protocol bytes
    pub signature: Option<Vec<u8>>, // network signature over envelope (without signature field)
}

impl TssEnvelope {
    pub fn new(
        protocol_version: String,
        session_id: [u8; 32],
        wallet: [u8; 20],
        chain_id: u64,
        participant_id: u8,
        round: u8,
        message_type: String,
        digest: [u8; 32],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version,
            session_id,
            wallet,
            chain_id,
            participant_id,
            round,
            message_type,
            digest,
            payload,
            signature: None,
        }
    }

    /// Bytes to sign for network authentication (excludes signature field)
    pub fn to_sign_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.protocol_version.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.wallet);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.push(self.participant_id);
        out.push(self.round);
        out.extend_from_slice(self.message_type.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn sign(&mut self, keypair: &crate::identity::NetworkKeypair) {
        let bytes = self.to_sign_bytes();
        let sig = keypair.sign(&bytes);
        self.signature = Some(sig.to_vec());
    }

    pub fn verify(&self, identity: &crate::identity::ParticipantIdentity) -> bool {
        if self.participant_id != identity.id {
            return false;
        }
        if !identity.check_wallet(&self.wallet, self.chain_id) {
            return false;
        }
        let Some(sig_bytes) = &self.signature else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig_bytes) else {
            return false;
        };
        identity.verify(&self.to_sign_bytes(), &sig)
    }

    /// Validate envelope against expected session context — prevents cross-session/wallet replay
    pub fn validate_against(
        &self,
        expected_session: &[u8; 32],
        expected_wallet: &[u8; 20],
        expected_chain: u64,
        expected_digest: &[u8; 32],
        expected_version: &str,
    ) -> Result<(), String> {
        if &self.session_id != expected_session {
            return Err(format!(
                "session_id mismatch: expected {}, got {}",
                hex::encode(expected_session),
                hex::encode(self.session_id)
            ));
        }
        if &self.wallet != expected_wallet {
            return Err("wallet mismatch".into());
        }
        if self.chain_id != expected_chain {
            return Err("chain_id mismatch".into());
        }
        if &self.digest != expected_digest {
            return Err("digest mismatch".into());
        }
        if self.protocol_version != expected_version {
            return Err("protocol_version mismatch".into());
        }
        if self.round == 0 || self.round > 10 {
            return Err("invalid round".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{NetworkKeypair, ParticipantIdentity};

    #[test]
    fn envelope_sign_verify_and_binding() {
        let kp = NetworkKeypair::generate();
        let id = ParticipantIdentity::new(1, kp.verifying_key().clone(), [0x11; 20], 31337);
        let mut env = TssEnvelope::new(
            "synedrion/0.3-cggmp24".into(),
            [0xAA; 32],
            [0x11; 20],
            31337,
            1,
            1,
            "InteractiveSigning".into(),
            [0xBB; 32],
            vec![1, 2, 3],
        );
        env.sign(&kp);
        assert!(env.verify(&id));
        // Wrong participant
        let mut env2 = env.clone();
        env2.participant_id = 2;
        assert!(!env2.verify(&id));
        // Cross-session replay
        assert!(env
            .validate_against(
                &[0xAA; 32],
                &[0x11; 20],
                31337,
                &[0xBB; 32],
                "synedrion/0.3-cggmp24"
            )
            .is_ok());
        assert!(env
            .validate_against(
                &[0xFF; 32],
                &[0x11; 20],
                31337,
                &[0xBB; 32],
                "synedrion/0.3-cggmp24"
            )
            .is_err());
        // Digest substitution
        assert!(env
            .validate_against(
                &[0xAA; 32],
                &[0x11; 20],
                31337,
                &[0xCC; 32],
                "synedrion/0.3-cggmp24"
            )
            .is_err());
    }
}
