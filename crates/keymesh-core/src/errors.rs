//! Shared error type for the KeyMesh core.

use std::fmt;

/// Errors produced by protocol state machines, policy evaluation, and the
/// cryptographic boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeymeshError {
    /// Input failed validation (lengths, formats, invariants).
    InvalidInput(String),
    /// A state transition was attempted that is not allowed.
    InvalidStateTransition { from: String, attempted: String },
    /// The actor is not authorized to perform this operation.
    Unauthorized(String),
    /// The referenced entity does not exist.
    NotFound(String),
    /// A quorum/threshold requirement was not met.
    ThresholdNotMet { required: usize, actual: usize },
    /// The same actor approved the same recovery request twice.
    DuplicateApproval(String),
    /// A timelock has not elapsed yet.
    TimelockActive { remaining_seconds: u64 },
    /// A signed transaction's expiry has passed.
    Expired { expiry: u64, now: u64 },
    /// The crypto provider rejected an operation or produced invalid output.
    CryptoOperationFailed(String),
}

impl fmt::Display for KeymeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeymeshError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            KeymeshError::InvalidStateTransition { from, attempted } => {
                write!(f, "invalid state transition: {from} -> {attempted}")
            }
            KeymeshError::Unauthorized(who) => write!(f, "unauthorized: {who}"),
            KeymeshError::NotFound(what) => write!(f, "not found: {what}"),
            KeymeshError::ThresholdNotMet { required, actual } => {
                write!(f, "threshold not met: required {required}, got {actual}")
            }
            KeymeshError::DuplicateApproval(who) => {
                write!(f, "duplicate approval: {who} already approved")
            }
            KeymeshError::TimelockActive { remaining_seconds } => {
                write!(f, "timelock active: {remaining_seconds} seconds remaining")
            }
            KeymeshError::Expired { expiry, now } => {
                write!(f, "transaction expired: expiry {expiry}, now {now}")
            }
            KeymeshError::CryptoOperationFailed(msg) => {
                write!(f, "crypto operation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for KeymeshError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_stable() {
        let e = KeymeshError::ThresholdNotMet {
            required: 3,
            actual: 2,
        };
        assert_eq!(e.to_string(), "threshold not met: required 3, got 2");

        let e = KeymeshError::InvalidStateTransition {
            from: "completed".into(),
            attempted: "cancel".into(),
        };
        assert_eq!(
            e.to_string(),
            "invalid state transition: completed -> cancel"
        );
    }
}
