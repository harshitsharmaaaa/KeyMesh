//! Transaction authorization policy evaluation.
//!
//! Policies map transaction classes to required authorization weight and
//! optional timelocks. Evaluation is pure: the same policy and transaction
//! always yield the same decision, which makes on-chain and off-chain
//! enforcement verifiable against each other.
//!
//! ## Maturity: PROTOTYPE
//! Value thresholds use u128 wei amounts; the contract-side PolicyManager will
//! mirror these semantics (see docs/protocol/transaction-policy.md).

use crate::errors::KeymeshError;

/// Classes of transactions the protocol distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionClass {
    /// Everyday transfers: device signature is sufficient.
    Normal,
    /// Large or sensitive transfers: device + guardian quorum.
    HighValue,
    /// Guardian set changes.
    GuardianManagement,
    /// Policy changes themselves.
    PolicyUpdate,
    /// Protocol-level recovery operations.
    Recovery,
}

/// Authorization rule attached to a transaction class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub class: TransactionClass,
    /// Total guardian/device weight required for approval.
    pub required_weight: u32,
    /// Optional timelock applied before execution, in seconds.
    pub timelock_seconds: u64,
}

/// A wallet's authorization policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub rules: Vec<PolicyRule>,
    /// Fallback threshold for classes without an explicit rule.
    pub default_weight: u32,
}

/// The decision produced by evaluating a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// Sufficient approvals present; may execute (after any timelock).
    Authorized,
    /// More approvals required before execution.
    NeedsApprovals { missing_weight: u32 },
    /// A timelock must elapse after threshold before execution.
    TimelockActive { remaining_seconds: u64 },
}

impl Policy {
    /// A sensible default policy matching the conceptual model:
    /// normal -> device only; high-value -> device + guardians; management
    /// operations get conservative defaults.
    pub fn standard() -> Self {
        Self {
            rules: vec![
                PolicyRule {
                    class: TransactionClass::Normal,
                    required_weight: 1,
                    timelock_seconds: 0,
                },
                PolicyRule {
                    class: TransactionClass::HighValue,
                    required_weight: 2,
                    timelock_seconds: 0,
                },
                PolicyRule {
                    class: TransactionClass::GuardianManagement,
                    required_weight: 2,
                    timelock_seconds: 24 * 3600,
                },
                PolicyRule {
                    class: TransactionClass::PolicyUpdate,
                    required_weight: 2,
                    timelock_seconds: 48 * 3600,
                },
                PolicyRule {
                    class: TransactionClass::Recovery,
                    required_weight: 3,
                    timelock_seconds: 7 * 24 * 3600,
                },
            ],
            default_weight: 1,
        }
    }

    fn rule_for(&self, class: TransactionClass) -> PolicyRule {
        self.rules
            .iter()
            .find(|r| r.class == class)
            .cloned()
            .unwrap_or(PolicyRule {
                class,
                required_weight: self.default_weight,
                timelock_seconds: 0,
            })
    }

    /// Evaluate whether the supplied approval weight satisfies `class`.
    ///
    /// `seconds_since_threshold` is 0 while below threshold; callers pass the
    /// elapsed time once the quorum has been reached.
    pub fn evaluate(
        &self,
        class: TransactionClass,
        approval_weight: u32,
        seconds_since_threshold: u64,
    ) -> Result<AuthorizationDecision, KeymeshError> {
        let rule = self.rule_for(class);

        if approval_weight < rule.required_weight {
            return Ok(AuthorizationDecision::NeedsApprovals {
                missing_weight: rule.required_weight - approval_weight,
            });
        }
        if rule.timelock_seconds > 0 && seconds_since_threshold < rule.timelock_seconds {
            return Ok(AuthorizationDecision::TimelockActive {
                remaining_seconds: rule.timelock_seconds - seconds_since_threshold,
            });
        }
        Ok(AuthorizationDecision::Authorized)
    }

    /// The value (in wei) at or above which a transfer is classified
    /// high-value. Returns None when no classification boundary exists.
    pub fn high_value_threshold_wei(&self) -> Option<u128> {
        // Prototype constant; Phase 1 moves this into per-wallet policy state.
        Some(1_000_000_000_000_000_000) // 1 ETH in wei
    }

    /// Classify a transfer by value using the policy boundaries.
    pub fn classify_transfer(&self, value_wei: u128) -> Result<TransactionClass, KeymeshError> {
        match self.high_value_threshold_wei() {
            Some(threshold) if value_wei >= threshold => Ok(TransactionClass::HighValue),
            Some(_) => Ok(TransactionClass::Normal),
            None => Err(KeymeshError::InvalidInput(
                "policy has no value classification boundary".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_transfers_need_device_only() {
        let policy = Policy::standard();
        assert_eq!(
            policy.evaluate(TransactionClass::Normal, 1, 0).unwrap(),
            AuthorizationDecision::Authorized
        );
        assert_eq!(
            policy.evaluate(TransactionClass::Normal, 0, 0).unwrap(),
            AuthorizationDecision::NeedsApprovals { missing_weight: 1 }
        );
    }

    #[test]
    fn high_value_needs_quorum() {
        let policy = Policy::standard();
        assert_eq!(
            policy.evaluate(TransactionClass::HighValue, 1, 0).unwrap(),
            AuthorizationDecision::NeedsApprovals { missing_weight: 1 }
        );
        assert_eq!(
            policy.evaluate(TransactionClass::HighValue, 2, 0).unwrap(),
            AuthorizationDecision::Authorized
        );
    }

    #[test]
    fn recovery_enforces_timelock() {
        let policy = Policy::standard();
        let week = 7 * 24 * 3600;
        assert_eq!(
            policy.evaluate(TransactionClass::Recovery, 3, 0).unwrap(),
            AuthorizationDecision::TimelockActive {
                remaining_seconds: week
            }
        );
        assert_eq!(
            policy
                .evaluate(TransactionClass::Recovery, 3, week)
                .unwrap(),
            AuthorizationDecision::Authorized
        );
    }

    #[test]
    fn classify_by_value() {
        let policy = Policy::standard();
        let one_eth = 1_000_000_000_000_000_000u128;
        assert_eq!(
            policy.classify_transfer(one_eth).unwrap(),
            TransactionClass::HighValue
        );
        assert_eq!(
            policy.classify_transfer(1).unwrap(),
            TransactionClass::Normal
        );
    }

    #[test]
    fn unknown_class_falls_back_to_default() {
        let mut policy = Policy::standard();
        policy.rules.clear();
        assert_eq!(
            policy
                .evaluate(TransactionClass::PolicyUpdate, 1, 0)
                .unwrap(),
            AuthorizationDecision::Authorized
        );
    }
}
