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
}
