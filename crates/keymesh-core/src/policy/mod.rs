//! Transaction authorization policy evaluation — reference semantics for the
//! on-chain `PolicyManager` contract (Phase 1.3).
//!
//! This module mirrors `contracts/ethereum/src/PolicyManager.sol` exactly:
//! same classification precedence, same value-threshold boundary, and the
//! same policy-version invalidation semantics. It is intentionally free of
//! cryptography and I/O; classification is a pure function so off-chain
//! previews can be verified against on-chain decisions.
//!
//! Separation of concerns (protocol invariant):
//!   - device signing proves WHO authorized a request,
//!   - THIS module determines WHAT authorization is required,
//!   - the recovery state machine changes WHO controls the wallet.
//!
//! No TSS/MPC exists here. Future authorization modes may extend
//! [`AuthorizationMode`] but must not reorder existing discriminants.

/// Authorization modes, numbered identically to the Solidity enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorizationMode {
    /// A registered-device signature is sufficient.
    DeviceOnly = 0,
    /// The device signature PLUS a guardian-approved transaction
    /// authorization bound to the exact canonical transaction digest.
    DevicePlusGuardians = 1,
}

impl AuthorizationMode {
    pub fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            0 => Some(AuthorizationMode::DeviceOnly),
            1 => Some(AuthorizationMode::DevicePlusGuardians),
            _ => None,
        }
    }
}

/// A wallet's policy configuration — the Rust mirror of
/// `IPolicyManager.PolicyConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Applied when no stronger rule matches.
    pub default_mode: AuthorizationMode,
    /// Wei; strictly ABOVE this value requires guardians (value == threshold
    /// stays with the default rule — inclusive boundary).
    pub value_threshold_wei: u128,
    /// Quorum snapshotted into transaction-authorization requests.
    pub guardian_approvals_required: u32,
    /// Bumped on every configuration change; version 0 means "unconfigured".
    pub version: u64,
}

impl PolicyConfig {
    /// Unconfigured wallets preserve exact Phase 1.1 behavior: everything is
    /// DEVICE_ONLY except the structural policy-administration rule.
    pub fn unconfigured() -> Self {
        Self {
            default_mode: AuthorizationMode::DeviceOnly,
            value_threshold_wei: 0,
            guardian_approvals_required: 0,
            version: 0,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.version != 0
    }

    /// Effective quorum for NEW authorization requests. Unconfigured wallets
    /// clamp to one guardian minimum — never zero, otherwise a single
    /// guardian could auto-authorize anything during bootstrap.
    pub fn effective_request_quorum(&self) -> u32 {
        if self.guardian_approvals_required == 0 {
            1
        } else {
            self.guardian_approvals_required
        }
    }
}

/// Inputs describing a hypothetical transaction for classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView<'a> {
    /// Recipient address bytes (20 for EVM; opaque here).
    pub to: &'a [u8],
    /// Wei value.
    pub value_wei: u128,
    /// Calldata; restrictions consider the first 4 bytes only when at least
    /// 4 bytes are present (empty/short calldata never matches selectors).
    pub data: &'a [u8],
}

/// Deterministic classification, precedence order (first match wins):
///
///   1. policy-administration selector on the PolicyManager itself
///      -> DEVICE_PLUS_GUARDIANS (structural anti-downgrade rule; holds even
///      for unconfigured wallets),
///   2. restricted calldata selector           -> DEVICE_PLUS_GUARDIANS,
///   3. restricted destination                 -> DEVICE_PLUS_GUARDIANS,
///   4. value > threshold                      -> DEVICE_PLUS_GUARDIANS,
///   5. otherwise                              -> wallet default mode.
///
/// `selector_restricted` / `destination_restricted` are resolved by the
/// caller against its own set storage; `to_is_policy_admin_with_admin_selector`
/// combines the destination and selector checks for the administration rule.
pub fn classify(
    config: &PolicyConfig,
    to_is_policy_manager: bool,
    selector_restricted: bool,
    destination_restricted: bool,
    tx: TransactionView<'_>,
) -> AuthorizationMode {
    // 1. Structural rule: mutating the PolicyManager always requires
    //    guardians, even before any configuration exists.
    let has_selector = tx.data.len() >= 4;
    if to_is_policy_manager && has_selector && selector_restricted {
        return AuthorizationMode::DevicePlusGuardians;
    }
    // Unconfigured wallets preserve exact Phase 1.1 behavior.
    if !config.is_configured() {
        return AuthorizationMode::DeviceOnly;
    }
    // 2. Explicitly restricted calldata selector.
    if has_selector && selector_restricted {
        return AuthorizationMode::DevicePlusGuardians;
    }
    // 3. Restricted destination.
    if destination_restricted {
        return AuthorizationMode::DevicePlusGuardians;
    }
    // 4. Value threshold (strictly above; boundary is inclusive to default).
    if tx.value_wei > config.value_threshold_wei {
        return AuthorizationMode::DevicePlusGuardians;
    }
    // 5. Wallet default.
    config.default_mode
}

/// Policy-version race semantics: a transaction authorization created under
/// `request_version` is valid only while the wallet's policy version equals
/// it. ANY configuration change therefore invalidates all pending and
/// approved-but-unexecuted authorizations (documented Phase 1.3 choice).
pub fn is_authorization_version_valid(request_version: u64, current_version: u64) -> bool {
    request_version == current_version
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_ETH: u128 = 1_000_000_000_000_000_000;

    fn configured() -> PolicyConfig {
        PolicyConfig {
            default_mode: AuthorizationMode::DeviceOnly,
            value_threshold_wei: ONE_ETH,
            guardian_approvals_required: 2,
            version: 1,
        }
    }

    fn tx(value_wei: u128, data: &'static [u8]) -> TransactionView<'static> {
        TransactionView {
            to: &[0xAA; 20],
            value_wei,
            data,
        }
    }

    #[test]
    fn unconfigured_wallets_are_device_only() {
        let config = PolicyConfig::unconfigured();
        assert_eq!(
            classify(&config, false, false, false, tx(5 * ONE_ETH, b"")),
            AuthorizationMode::DeviceOnly
        );
    }

    #[test]
    fn structural_admin_rule_holds_even_unconfigured() {
        let config = PolicyConfig::unconfigured();
        let admin_data: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x00];
        assert_eq!(
            classify(&config, true, true, false, tx(0, admin_data)),
            AuthorizationMode::DevicePlusGuardians,
            "mutating the PolicyManager can never be downgraded"
        );
    }

    #[test]
    fn admin_rule_requires_policy_manager_destination_and_selector() {
        let config = configured();
        let admin_data: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        // Same selector, different destination: not the admin rule...
        assert_eq!(
            classify(&config, false, true, false, tx(0, admin_data)),
            AuthorizationMode::DevicePlusGuardians,
            "...but still caught by the explicit restriction in this example"
        );
        // Admin destination without an admin selector falls through rules.
        assert_eq!(
            classify(&config, true, false, false, tx(0, b"")),
            AuthorizationMode::DeviceOnly
        );
    }

    #[test]
    fn value_boundary_is_inclusive_to_default() {
        let config = configured();
        assert_eq!(
            classify(&config, false, false, false, tx(ONE_ETH, b"")),
            AuthorizationMode::DeviceOnly,
            "value == threshold stays with the default rule"
        );
        assert_eq!(
            classify(&config, false, false, false, tx(ONE_ETH + 1, b"")),
            AuthorizationMode::DevicePlusGuardians
        );
    }

    #[test]
    fn restricted_destination_forces_guardians() {
        let config = configured();
        assert_eq!(
            classify(&config, false, false, true, tx(0, b"")),
            AuthorizationMode::DevicePlusGuardians,
            "regardless of value"
        );
    }

    #[test]
    fn short_calldata_never_matches_selectors() {
        let config = configured();
        for len in 0..4usize {
            let data = vec![0xAB; len];
            let view = TransactionView {
                to: &[0xAA; 20],
                value_wei: 0,
                data: &data,
            };
            assert_eq!(
                classify(&config, false, true, false, view),
                AuthorizationMode::DeviceOnly,
                "len={len} cannot match a selector rule"
            );
        }
    }

    #[test]
    fn restricted_selector_forces_guardians() {
        let config = configured();
        let data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        assert_eq!(
            classify(&config, false, true, false, tx(0, data)),
            AuthorizationMode::DevicePlusGuardians
        );
    }

    #[test]
    fn default_mode_applies_when_nothing_stronger_matches() {
        let config = PolicyConfig {
            default_mode: AuthorizationMode::DevicePlusGuardians,
            value_threshold_wei: u128::MAX,
            guardian_approvals_required: 2,
            version: 3,
        };
        assert_eq!(
            classify(&config, false, false, false, tx(0, b"")),
            AuthorizationMode::DevicePlusGuardians
        );
    }

    #[test]
    fn effective_request_quorum_never_zero() {
        assert_eq!(PolicyConfig::unconfigured().effective_request_quorum(), 1);
        assert_eq!(configured().effective_request_quorum(), 2);
    }

    #[test]
    fn any_version_change_invalidates_authorizations() {
        assert!(is_authorization_version_valid(3, 3));
        assert!(!is_authorization_version_valid(3, 4));
        assert!(!is_authorization_version_valid(4, 3));
    }

    #[test]
    fn mode_discriminants_match_solidity_enum_order() {
        assert_eq!(AuthorizationMode::DeviceOnly as u8, 0);
        assert_eq!(AuthorizationMode::DevicePlusGuardians as u8, 1);
        assert_eq!(
            AuthorizationMode::from_discriminant(0),
            Some(AuthorizationMode::DeviceOnly)
        );
        assert_eq!(
            AuthorizationMode::from_discriminant(1),
            Some(AuthorizationMode::DevicePlusGuardians)
        );
        assert_eq!(AuthorizationMode::from_discriminant(2), None);
    }
}
