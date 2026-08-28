//! TSS/MPC signing abstraction — Phase 2.1 design only.
//!
//! Maturity: DESIGNED, NOT IMPLEMENTED, NOT AUDITED.
//! Type-only abstractions for the future threshold signing layer.
//! No cryptographic implementation, no private key handling, no fake MPC.

use crate::errors::KeymeshError;

/// Branded participant identifier (hex fingerprint of identity key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParticipantId(pub String);

/// Signing protocol version (e.g., "cggmp21/v1").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningProtocolVersion(pub String);

/// Session identifier (32-byte hex with 0x prefix).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

pub const SIGNING_PROTOCOL_V1: &str = "cggmp21/v1";

/// Signing session status — monotonic terminal states (TSS-INV-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningSessionStatus {
    Started,
    Aborted,
    Failed,
    Completed,
}

impl ParticipantId {
    pub fn new(fingerprint: &str) -> Result<Self, KeymeshError> {
        if !is_valid_participant_id(fingerprint) {
            return Err(KeymeshError::InvalidInput(
                "ParticipantId must be 0x hex 20-32 bytes".into(),
            ));
        }
        Ok(Self(fingerprint.to_ascii_lowercase()))
    }
}

pub fn is_valid_participant_id(value: &str) -> bool {
    if !value.starts_with("0x") {
        return false;
    }
    let hex = &value[2..];
    if hex.len() < 40 || hex.len() > 64 || hex.len() % 2 != 0 {
        return false;
    }
    hex.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_signing_protocol_version(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '/')
}

pub fn is_valid_session_id(value: &str) -> bool {
    if !value.starts_with("0x") || value.len() != 66 {
        return false;
    }
    value[2..].chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Clone)]
pub struct SigningSession {
    pub session_id: SessionId,
    pub wallet: String,
    pub digest: String,
    pub nonce: u64,
    pub policy_version: u64,
    pub protocol_version: SigningProtocolVersion,
    pub participants: Vec<ParticipantId>,
    pub threshold: usize,
    pub status: SigningSessionStatus,
}

impl SigningSession {
    pub fn transition(mut self, to: SigningSessionStatus) -> Result<Self, KeymeshError> {
        if self.status != SigningSessionStatus::Started {
            return Err(KeymeshError::InvalidStateTransition {
                from: format!("{:?}", self.status),
                attempted: format!("{to:?}"),
            });
        }
        if to == SigningSessionStatus::Started {
            return Err(KeymeshError::InvalidInput(
                "cannot transition back to Started".into(),
            ));
        }
        self.status = to;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_id_validation() {
        assert!(is_valid_participant_id(
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        ));
        assert!(!is_valid_participant_id("not-hex"));
        assert!(ParticipantId::new("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").is_ok());
        assert!(ParticipantId::new("bad").is_err());
    }

    #[test]
    fn protocol_version_validation() {
        assert!(is_valid_signing_protocol_version("cggmp21/v1"));
        assert!(is_valid_signing_protocol_version("gg20/v2"));
        assert!(!is_valid_signing_protocol_version(""));
        assert!(!is_valid_signing_protocol_version("no-slash"));
    }

    #[test]
    fn session_id_validation() {
        assert!(is_valid_session_id(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!is_valid_session_id("0xabc"));
    }

    #[test]
    fn session_lifecycle_monotonic() {
        let p1 = ParticipantId::new("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let p2 = ParticipantId::new("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let sess = SigningSession {
            session_id: SessionId(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            wallet: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            digest: "0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a".into(),
            nonce: 0,
            policy_version: 1,
            protocol_version: SigningProtocolVersion(SIGNING_PROTOCOL_V1.into()),
            participants: vec![p1, p2],
            threshold: 2,
            status: SigningSessionStatus::Started,
        };
        let completed = sess
            .clone()
            .transition(SigningSessionStatus::Completed)
            .unwrap();
        assert_eq!(completed.status, SigningSessionStatus::Completed);
        assert!(completed.transition(SigningSessionStatus::Aborted).is_err());

        let aborted = sess.transition(SigningSessionStatus::Aborted).unwrap();
        assert_eq!(aborted.status, SigningSessionStatus::Aborted);
        assert!(aborted.transition(SigningSessionStatus::Completed).is_err());
    }
}
