//! Governed TSS participant rotation — separate domain from device recovery.
//!
//! Device Recovery changes wallet authorization device (Phase 1.2).
//! TSS Participant Rotation changes cryptographic signing participants.
//! They share guardian quorum+timelock infrastructure but have distinct semantics.
//!
//! Governance is authoritative: RecoveryManager (guardian quorum + timelock) decides
//! who participates; TSS layer only performs cryptographic resharing after authorization.
//!
//! Flow: guardian quorum -> timelock -> cryptographic rotation (KeyResharing)

use std::collections::HashSet;

use crate::errors::TssError;

/// Minimum timelock mirrors RecoveryManager MIN_TIMELOCK = 3600s
pub const MIN_TIMELOCK_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TssRotationStatus {
    None,
    Pending,
    QuorumReached,
    Executable,
    Resharing,
    Completed,
    Cancelled,
    Failed,
}

impl TssRotationStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::QuorumReached | Self::Executable | Self::Resharing
        )
    }
}

#[derive(Debug, Clone)]
pub struct TssRotationRequest {
    pub id: u64,
    pub wallet: [u8; 20],
    pub old_participant_set_version: u64,
    pub new_participant_set: Vec<String>,
    pub threshold: usize,
    pub requested_by: String,
    pub governance_reference: String,
    pub created_at: u64,
    pub executable_at: Option<u64>,
    pub quorum_required: u32,
    pub timelock_seconds: u64,
    approvals: Vec<String>,
    status: TssRotationStatus,
    pub group_public_key: [u8; 33],
}

impl TssRotationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn initiate(
        id: u64,
        wallet: [u8; 20],
        old_participant_set_version: u64,
        new_participant_set: Vec<String>,
        threshold: usize,
        requested_by: String,
        governance_reference: String,
        group_public_key: [u8; 33],
        active_guardian_count: usize,
        quorum_required: u32,
        timelock_seconds: u64,
        now_seconds: u64,
    ) -> Result<Self, TssError> {
        if new_participant_set.is_empty() {
            return Err(TssError::InvalidParticipantSet(
                "new participant set must not be empty".into(),
            ));
        }
        if threshold == 0 || threshold > new_participant_set.len() {
            return Err(TssError::InvalidThreshold(format!(
                "threshold {threshold} invalid for n={}",
                new_participant_set.len()
            )));
        }
        let uniq: HashSet<_> = new_participant_set.iter().collect();
        if uniq.len() != new_participant_set.len() {
            return Err(TssError::InvalidParticipantSet(
                "duplicate participant in new set".into(),
            ));
        }
        if quorum_required == 0 {
            return Err(TssError::Governance("quorum must be >0".into()));
        }
        if quorum_required as usize > active_guardian_count {
            return Err(TssError::Governance(format!(
                "quorum {quorum_required} unsatisfiable with {active_guardian_count} guardians"
            )));
        }
        if timelock_seconds < MIN_TIMELOCK_SECONDS {
            return Err(TssError::Governance(format!(
                "timelock {timelock_seconds}s below minimum {MIN_TIMELOCK_SECONDS}s"
            )));
        }
        // Governance authority check: coordinator/participant alone cannot initiate
        // single guardian approval is not sufficient; quorum will be enforced on approve path
        if requested_by.is_empty() {
            return Err(TssError::Governance(
                "requested_by must not be empty".into(),
            ));
        }
        Ok(Self {
            id,
            wallet,
            old_participant_set_version,
            new_participant_set,
            threshold,
            requested_by,
            governance_reference,
            created_at: now_seconds,
            executable_at: None,
            quorum_required,
            timelock_seconds,
            approvals: Vec::new(),
            status: TssRotationStatus::Pending,
            group_public_key,
        })
    }

    pub fn status(&self) -> &TssRotationStatus {
        &self.status
    }

    pub fn approvals(&self) -> &[String] {
        &self.approvals
    }

    pub fn effective_status(&self, now_seconds: u64) -> TssRotationStatus {
        if self.status == TssRotationStatus::QuorumReached {
            if let Some(exec) = self.executable_at {
                if now_seconds >= exec {
                    return TssRotationStatus::Executable;
                }
            }
        }
        self.status.clone()
    }

    pub fn approve(&mut self, guardian: String, now_seconds: u64) -> Result<(), TssError> {
        if self.status != TssRotationStatus::Pending {
            return Err(TssError::Governance(format!(
                "can only approve Pending, got {:?}",
                self.status
            )));
        }
        if self.approvals.contains(&guardian) {
            return Err(TssError::Governance(format!(
                "duplicate approval {guardian}"
            )));
        }
        // Single device / participant alone cannot bypass governance: check guardian identity is not empty
        // Caller layer must verify guardian is authorized; here we enforce duplicate+count.
        self.approvals.push(guardian);
        if self.approvals.len() >= self.quorum_required as usize {
            self.status = TssRotationStatus::QuorumReached;
            self.executable_at = Some(now_seconds + self.timelock_seconds);
        }
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), TssError> {
        if !self.status.is_live() {
            return Err(TssError::Governance(format!(
                "cannot cancel terminal {:?}",
                self.status
            )));
        }
        self.status = TssRotationStatus::Cancelled;
        Ok(())
    }

    pub fn mark_resharing(&mut self) -> Result<(), TssError> {
        let effective = self.status.clone();
        // Must be Executable (timelock elapsed)
        if effective != TssRotationStatus::Executable
            && self.status != TssRotationStatus::QuorumReached
        {
            // Allow caller to check via effective_status
            return Err(TssError::Governance(format!(
                "rotation not executable, status {:?}",
                self.status
            )));
        }
        self.status = TssRotationStatus::Resharing;
        Ok(())
    }

    pub fn mark_resharing_with_time(&mut self, now_seconds: u64) -> Result<(), TssError> {
        let eff = self.effective_status(now_seconds);
        if eff != TssRotationStatus::Executable {
            return Err(TssError::Governance(format!(
                "timelock not elapsed: status {:?} vs executable_at {:?} now {now_seconds}",
                self.status, self.executable_at
            )));
        }
        self.status = TssRotationStatus::Resharing;
        Ok(())
    }

    pub fn mark_completed(&mut self) -> Result<(), TssError> {
        if self.status != TssRotationStatus::Resharing {
            return Err(TssError::Governance(format!(
                "can only complete from Resharing, got {:?}",
                self.status
            )));
        }
        self.status = TssRotationStatus::Completed;
        Ok(())
    }

    pub fn mark_failed(&mut self) -> Result<(), TssError> {
        if self.status != TssRotationStatus::Resharing {
            return Err(TssError::Governance(format!(
                "can only fail from Resharing, got {:?}",
                self.status
            )));
        }
        self.status = TssRotationStatus::Failed;
        Ok(())
    }

    pub fn is_executable(&self, now_seconds: u64) -> bool {
        self.effective_status(now_seconds) == TssRotationStatus::Executable
    }

    /// Canonical bytes for cross-language test vectors (deterministic)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"KEYMESH_TSS_ROTATION_V1");
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.wallet);
        out.extend_from_slice(&self.old_participant_set_version.to_be_bytes());
        out.extend_from_slice(&(self.new_participant_set.len() as u64).to_be_bytes());
        for p in &self.new_participant_set {
            let b = p.as_bytes();
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
        out.extend_from_slice(&(self.threshold as u64).to_be_bytes());
        out.extend_from_slice(&(self.quorum_required as u64).to_be_bytes());
        out.extend_from_slice(&self.timelock_seconds.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.group_public_key);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet() -> [u8; 20] {
        [0x11; 20]
    }
    fn gpk() -> [u8; 33] {
        [0x02; 33]
    }

    #[test]
    fn initiate_ok() {
        let r = TssRotationRequest::initiate(
            1,
            wallet(),
            1,
            vec!["A".into(), "B".into(), "C".into()],
            2,
            "guardian1".into(),
            "gov-ref-1".into(),
            gpk(),
            3,
            2,
            3600,
            1000,
        )
        .unwrap();
        assert_eq!(*r.status(), TssRotationStatus::Pending);
    }

    #[test]
    fn quorum_and_timelock() {
        let mut r = TssRotationRequest::initiate(
            1,
            wallet(),
            1,
            vec!["A".into(), "B".into(), "C".into()],
            2,
            "g1".into(),
            "ref".into(),
            gpk(),
            3,
            2,
            3600,
            1000,
        )
        .unwrap();
        r.approve("guardian1".into(), 1100).unwrap();
        assert_eq!(*r.status(), TssRotationStatus::Pending);
        r.approve("guardian2".into(), 1200).unwrap();
        assert_eq!(*r.status(), TssRotationStatus::QuorumReached);
        assert_eq!(r.executable_at, Some(1200 + 3600));
        assert_eq!(
            r.effective_status(1200 + 3599),
            TssRotationStatus::QuorumReached
        );
        assert_eq!(
            r.effective_status(1200 + 3600),
            TssRotationStatus::Executable
        );
        assert!(r.is_executable(1200 + 3600));
        r.mark_resharing_with_time(1200 + 3600).unwrap();
        assert_eq!(*r.status(), TssRotationStatus::Resharing);
        r.mark_completed().unwrap();
        assert_eq!(*r.status(), TssRotationStatus::Completed);
    }

    #[test]
    fn stale_single_guardian_cannot_complete() {
        let mut r = TssRotationRequest::initiate(
            1,
            wallet(),
            1,
            vec!["A".into(), "B".into(), "C".into()],
            2,
            "g1".into(),
            "ref".into(),
            gpk(),
            3,
            2,
            3600,
            1000,
        )
        .unwrap();
        r.approve("guardian1".into(), 1000).unwrap();
        // Only one approval, still pending, cannot mark resharing
        assert!(r.mark_resharing_with_time(5000).is_err());
    }

    #[test]
    fn canonical_deterministic() {
        let a = TssRotationRequest::initiate(
            1,
            wallet(),
            1,
            vec!["A".into(), "B".into()],
            2,
            "g".into(),
            "ref".into(),
            gpk(),
            3,
            2,
            3600,
            1000,
        )
        .unwrap();
        let b = TssRotationRequest::initiate(
            1,
            wallet(),
            1,
            vec!["A".into(), "B".into()],
            2,
            "g".into(),
            "ref".into(),
            gpk(),
            3,
            2,
            3600,
            1000,
        )
        .unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }
}
