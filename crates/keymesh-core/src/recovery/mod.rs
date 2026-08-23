//! Guardian recovery state machine.
//!
//! Pure, deterministic transitions with an injectable clock so tests can move
//! through timelocks without sleeping. The on-chain RecoveryManager contract
//! must implement the same machine (see docs/protocol/recovery.md); this
//! module is the reference semantics.

use crate::errors::KeymeshError;

/// States of a recovery request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Waiting for guardian approvals to reach the threshold.
    Pending,
    /// Threshold reached; timelock window running.
    TimelockActive,
    /// Timelock elapsed and recovery finalized: new device authorized.
    Completed,
    /// Cancelled by an authorized party before completion.
    Cancelled,
    /// Expired without reaching threshold within the validity window.
    Expired,
}

impl RecoveryState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            RecoveryState::Completed | RecoveryState::Cancelled | RecoveryState::Expired
        )
    }
}

impl std::fmt::Display for RecoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecoveryState::Pending => "pending",
            RecoveryState::TimelockActive => "timelock_active",
            RecoveryState::Completed => "completed",
            RecoveryState::Cancelled => "cancelled",
            RecoveryState::Expired => "expired",
        };
        write!(f, "{s}")
    }
}

/// A recovery request aggregate.
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub state: RecoveryState,
    /// Guardian ids that have approved (order = arrival, no duplicates).
    approvals: Vec<String>,
    /// Accumulated weight of approvals received so far.
    approved_weight: u32,
    /// Weighted quorum required from active guardians.
    pub required_weight: u32,
    /// Timelock duration applied once the threshold is reached, in seconds.
    pub timelock_seconds: u64,
    /// Timestamp (seconds) when the timelock ends; set at threshold time.
    pub timelock_ends_at: Option<u64>,
}

impl RecoveryRequest {
    pub fn new(required_weight: u32, timelock_seconds: u64) -> Result<Self, KeymeshError> {
        if required_weight == 0 {
            return Err(KeymeshError::InvalidInput(
                "recovery threshold must be greater than zero".into(),
            ));
        }
        Ok(Self {
            state: RecoveryState::Pending,
            approvals: Vec::new(),
            approved_weight: 0,
            required_weight,
            timelock_seconds,
            timelock_ends_at: None,
        })
    }

    pub fn approvals(&self) -> &[String] {
        &self.approvals
    }

    /// Weight accumulated from approvals so far.
    pub fn approved_weight(&self) -> u32 {
        self.approved_weight
    }

    /// Record a guardian approval. Duplicate approvals are idempotent no-ops.
    ///
    /// `now_seconds` is provided by the caller (clock injection).
    pub fn approve(
        &mut self,
        guardian_id: impl Into<String>,
        weight: u32,
        now_seconds: u64,
    ) -> Result<(), KeymeshError> {
        match self.state {
            RecoveryState::Pending => {}
            other => {
                return Err(KeymeshError::InvalidStateTransition {
                    from: other.to_string(),
                    attempted: "approve".into(),
                })
            }
        }

        let id = guardian_id.into();
        if self.approvals.contains(&id) {
            return Ok(());
        }
        self.approved_weight += weight;
        self.approvals.push(id);

        if self.approved_weight >= self.required_weight {
            self.state = RecoveryState::TimelockActive;
            self.timelock_ends_at = Some(now_seconds + self.timelock_seconds);
        }
        Ok(())
    }

    /// Complete the recovery once the timelock has elapsed.
    pub fn complete(&mut self, now_seconds: u64) -> Result<(), KeymeshError> {
        match self.state {
            RecoveryState::TimelockActive => {}
            other => {
                return Err(KeymeshError::InvalidStateTransition {
                    from: other.to_string(),
                    attempted: "complete".into(),
                })
            }
        }
        let ends_at = self
            .timelock_ends_at
            .expect("timelock set when entering TimelockActive");
        if now_seconds < ends_at {
            return Err(KeymeshError::TimelockActive {
                remaining_seconds: ends_at - now_seconds,
            });
        }
        self.state = RecoveryState::Completed;
        Ok(())
    }

    /// Cancel from any non-terminal state.
    pub fn cancel(&mut self) -> Result<(), KeymeshError> {
        if self.state.is_terminal() {
            return Err(KeymeshError::InvalidStateTransition {
                from: self.state.to_string(),
                attempted: "cancel".into(),
            });
        }
        self.state = RecoveryState::Cancelled;
        Ok(())
    }

    /// Expire from any non-terminal state (e.g. validity window passed).
    pub fn expire(&mut self) -> Result<(), KeymeshError> {
        if self.state.is_terminal() {
            return Err(KeymeshError::InvalidStateTransition {
                from: self.state.to_string(),
                attempted: "expire".into(),
            });
        }
        self.state = RecoveryState::Expired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    #[test]
    fn pending_to_timelock_on_threshold() {
        let mut r = RecoveryRequest::new(3, DAY).unwrap();
        r.approve("g1", 1, 0).unwrap();
        assert_eq!(r.state, RecoveryState::Pending);
        r.approve("g2", 2, 100).unwrap();
        assert_eq!(r.state, RecoveryState::TimelockActive);
        assert_eq!(r.timelock_ends_at, Some(100 + DAY));
    }

    #[test]
    fn duplicate_approval_is_noop() {
        let mut r = RecoveryRequest::new(2, DAY).unwrap();
        r.approve("g1", 1, 0).unwrap();
        let weight_before = r.approved_weight();
        r.approve("g1", 1, 50).unwrap();
        assert_eq!(r.approved_weight(), weight_before);
        assert_eq!(r.approvals().len(), 1);
    }

    #[test]
    fn cannot_complete_before_timelock() {
        let mut r = RecoveryRequest::new(1, DAY).unwrap();
        r.approve("g1", 1, 0).unwrap();
        let err = r.complete(DAY - 1).unwrap_err();
        assert!(matches!(err, KeymeshError::TimelockActive { .. }));
        r.complete(DAY).unwrap();
        assert_eq!(r.state, RecoveryState::Completed);
    }

    #[test]
    fn terminal_states_reject_transitions() {
        let mut r = RecoveryRequest::new(1, DAY).unwrap();
        r.approve("g1", 1, 0).unwrap();
        r.cancel().unwrap();
        assert!(matches!(
            r.cancel(),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
        assert!(matches!(
            r.approve("g2", 1, 10),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn zero_threshold_is_invalid_input() {
        assert!(matches!(
            RecoveryRequest::new(0, DAY),
            Err(KeymeshError::InvalidInput(_))
        ));
    }

    #[test]
    fn expiry_from_pending() {
        let mut r = RecoveryRequest::new(5, DAY).unwrap();
        r.expire().unwrap();
        assert_eq!(r.state, RecoveryState::Expired);
    }
}
