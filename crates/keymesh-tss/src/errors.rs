use thiserror::Error;

#[derive(Debug, Error)]
pub enum TssError {
    #[error("invalid threshold: {0}")]
    InvalidThreshold(String),
    #[error("DKG failed: {0}")]
    DkgFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("session binding mismatch: {0}")]
    SessionMismatch(String),
    #[error("insufficient shares: have {have}, need {need}")]
    InsufficientShares { have: usize, need: usize },
    #[error("duplicate participant")]
    DuplicateParticipant,
    #[error("unknown participant")]
    UnknownParticipant,
    #[error("aborted: {0}")]
    Aborted(String),
    #[error("lifecycle error: {0}")]
    Lifecycle(String),
    #[error("lifecycle locked: {0}")]
    LifecycleLocked(String),
    #[error("stale participant set version: expected {expected}, got {got}")]
    StaleVersion { expected: u64, got: u64 },
    #[error("retired: {0}")]
    Retired(String),
    #[error("governance error: {0}")]
    Governance(String),
    #[error("refresh failed: {0}")]
    RefreshFailed(String),
    #[error("rotation failed: {0}")]
    RotationFailed(String),
    #[error("invalid participant set: {0}")]
    InvalidParticipantSet(String),
}
