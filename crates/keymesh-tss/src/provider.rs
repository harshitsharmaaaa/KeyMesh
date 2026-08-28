//! Phase 2.4 — SigningProvider integration boundary.
//!
//! Provides `ThresholdEcdsaProvider` behind `SigningProvider` abstraction.
//! Single signer remains default; threshold is explicit opt-in via env/config.

use crate::dkg::{GroupPublicKey, ThresholdKeyMaterial};
use crate::errors::TssError;
use crate::session::{SessionBinding, SessionId};
use crate::signing::{threshold_sign, verify_signature, ThresholdSignature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningMode {
    Single,
    Threshold,
}

impl SigningMode {
    pub fn from_env() -> Self {
        match std::env::var("KEYMESH_SIGNING_MODE").as_deref() {
            Ok("threshold") => Self::Threshold,
            _ => Self::Single,
        }
    }
    pub fn is_threshold(&self) -> bool {
        matches!(self, Self::Threshold)
    }
}

#[derive(Debug, Clone)]
pub struct ThresholdParticipantSet {
    pub protocol_version: String,
    pub threshold: usize,
    pub total: usize,
    pub participant_ids: Vec<u8>,
    pub group_public_key: GroupPublicKey,
}

impl ThresholdParticipantSet {
    pub fn from_material(mat: &ThresholdKeyMaterial) -> Self {
        Self {
            protocol_version: "synedrion/0.3-cggmp24".into(),
            threshold: mat.threshold,
            total: mat.total,
            participant_ids: mat.participants.iter().map(|p| p.index).collect(),
            group_public_key: mat.group_public_key.clone(),
        }
    }
    pub fn verify_wallet_identity(&self, expected_wallet: &[u8; 20]) -> Result<(), TssError> {
        if &self.group_public_key.ethereum_address != expected_wallet {
            return Err(TssError::SessionMismatch(format!(
                "group address 0x{} != wallet 0x{}",
                hex::encode(self.group_public_key.ethereum_address),
                hex::encode(expected_wallet)
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    ThresholdNotSatisfied,
    InvalidParticipant,
    SessionMismatch,
    DigestMismatch,
    SigningFailed(String),
    WrongChain,
    MainnetNotAllowed,
}

pub trait SigningProvider {
    fn kind(&self) -> &'static str;
    fn protocol_version(&self) -> &str;
    fn capabilities(&self) -> Vec<String>;
}

pub struct SingleEcdsaProvider {
    pub protocol_version: String,
}

impl SingleEcdsaProvider {
    pub fn new() -> Self {
        Self {
            protocol_version: "ecdsa/single-v1".into(),
        }
    }
}

impl Default for SingleEcdsaProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningProvider for SingleEcdsaProvider {
    fn kind(&self) -> &'static str {
        "single"
    }
    fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
    fn capabilities(&self) -> Vec<String> {
        vec!["sign".into(), "verify".into()]
    }
}

pub struct ThresholdEcdsaProvider {
    material: ThresholdKeyMaterial,
    participant_set: ThresholdParticipantSet,
    chain_id: u64,
}

impl ThresholdEcdsaProvider {
    pub fn new(material: ThresholdKeyMaterial, chain_id: u64) -> Result<Self, TssError> {
        // Reject mainnet by default unless explicitly allowed
        if chain_id == 1 {
            // Phase 2.4: testnet only unless KEYMESH_ENABLE_MAINNET_TSS=true
            if std::env::var("KEYMESH_ENABLE_MAINNET_TSS").as_deref() != Ok("true") {
                return Err(TssError::SessionMismatch(
                    "mainnet not allowed for threshold provider (testnet only)".into(),
                ));
            }
        }
        let participant_set = ThresholdParticipantSet::from_material(&material);
        Ok(Self {
            material,
            participant_set,
            chain_id,
        })
    }

    pub fn participant_set(&self) -> &ThresholdParticipantSet {
        &self.participant_set
    }

    pub fn group_address(&self) -> [u8; 20] {
        self.material.group_public_key.ethereum_address
    }

    /// High-level sign operation — receives KEYMESH signing context,
    /// validates session binding, selects participants, executes real threshold signing.
    pub fn sign(
        &self,
        binding: &SessionBinding,
        subset: &[usize],
        session_id: &SessionId,
    ) -> Result<ThresholdSignature, TssError> {
        // Chain mismatch → fail closed
        if binding.chain_id != self.chain_id {
            return Err(TssError::SessionMismatch(format!(
                "chain mismatch: binding {} != provider {}",
                binding.chain_id, self.chain_id
            )));
        }
        // Threshold check already in threshold_sign, but pre-check for clearer error
        if subset.len() < self.participant_set.threshold {
            return Err(TssError::InsufficientShares {
                have: subset.len(),
                need: self.participant_set.threshold,
            });
        }
        // Unknown/duplicate handled in threshold_sign
        threshold_sign(&self.material, subset, binding, session_id)
    }

    pub fn verify(&self, digest: &[u8; 32], sig: &ThresholdSignature) -> bool {
        verify_signature(digest, sig, &self.material.group_public_key.verifying_key)
    }

    pub fn capabilities(&self) -> Vec<String> {
        vec![
            "dkg".into(),
            "sign".into(),
            "verify".into(),
            "session".into(),
        ]
    }
}

impl SigningProvider for ThresholdEcdsaProvider {
    fn kind(&self) -> &'static str {
        "threshold"
    }
    fn protocol_version(&self) -> &str {
        "synedrion/0.3-cggmp24"
    }
    fn capabilities(&self) -> Vec<String> {
        self.capabilities()
    }
}
