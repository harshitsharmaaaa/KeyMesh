use crate::session::SessionId;
use crate::signing::ThresholdSignature;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningTranscript {
    pub participant_indices: Vec<u8>,
    pub protocol_version: String,
    pub session_id: SessionId,
    pub digest: [u8; 32],
    pub chain_id: u64,
    pub wallet: [u8; 20],
    pub nonce: u64,
    pub policy_version: u64,
    pub round_count: usize,
    pub message_types: Vec<String>,
    pub message_ordering: Vec<String>,
    pub final_signature: Option<ThresholdSignature>,
    pub status: String,
}

impl SigningTranscript {
    pub fn new_success(
        participants: Vec<u8>,
        session_id: SessionId,
        digest: [u8; 32],
        chain_id: u64,
        wallet: [u8; 20],
        nonce: u64,
        policy_version: u64,
        sig: ThresholdSignature,
    ) -> Self {
        Self {
            participant_indices: participants,
            protocol_version: "synedrion/0.3-cggmp24".into(),
            session_id,
            digest,
            chain_id,
            wallet,
            nonce,
            policy_version,
            round_count: 3,
            message_types: vec![
                "KeyInit".into(),
                "KeyResharing".into(),
                "AuxGen".into(),
                "InteractiveSigning".into(),
            ],
            message_ordering: vec!["broadcast".into()],
            final_signature: Some(sig),
            status: "Completed".into(),
        }
    }
}
