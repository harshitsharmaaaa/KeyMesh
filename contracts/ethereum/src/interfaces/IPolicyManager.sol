// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPolicyManager
/// @notice Per-wallet transaction authorization policies.
interface IPolicyManager {
    enum TxClass {
        Normal,
        HighValue,
        GuardianManagement,
        PolicyUpdate,
        Recovery
    }

    struct Policy {
        uint96 normalWeight; // device weight required for normal txs
        uint96 highValueWeight; // guardian weight required on top of device
        uint256 highValueWeiBoundary; // value at/above which a tx is high-value
        uint96 recoveryWeight; // guardian quorum for recovery
        uint64 recoveryTimelock; // seconds; enforced by RecoveryManager
    }

    event PolicySet(address indexed wallet, Policy policy);

    error InvalidPolicy(string reason);

    /// @notice Stores the policy for `wallet`. Only callable by the wallet.
    function setPolicy(address wallet, Policy calldata policy) external;

    /// @notice Returns the stored policy for `wallet`.
    function policyOf(address wallet) external view returns (Policy memory);

    /// @notice Required guardian/device weight for a transaction class.
    function requiredWeight(address wallet, TxClass txClass) external view returns (uint256);
}
