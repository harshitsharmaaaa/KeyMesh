// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IRecoveryManager
/// @notice Guardian-quorum recovery with a mandatory timelock.
interface IRecoveryManager {
    enum RecoveryState {
        None,
        Pending,
        TimelockActive,
        Completed,
        Cancelled
    }

    event RecoveryInitiated(address indexed wallet, address newDevice, uint256 requiredWeight);
    event RecoveryApproved(address indexed wallet, address indexed guardian, uint256 totalWeight);
    event RecoveryTimelockStarted(address indexed wallet, uint64 timelockEndsAt);
    event RecoveryCompleted(address indexed wallet, address newDevice);
    event RecoveryCancelled(address indexed wallet);

    error RecoveryAlreadyActive();
    error NoActiveRecovery();
    error NotRegisteredGuardian(address guardian);
    error DuplicateApproval(address guardian);
    error ThresholdNotMet(uint256 required, uint256 current);
    error TimelockNotElapsed(uint64 endsAt, uint256 nowTs);
    error TimelockTooShort();

    /// @notice Opens a recovery for `wallet` authorizing `newDevice` once done.
    /// @param requiredWeight Guardian weight quorum (from the policy engine).
    function initiateRecovery(
        address wallet,
        address newDevice,
        uint256 requiredWeight,
        uint64 timelockSeconds
    ) external;

    /// @notice Records an approval from an active guardian of `wallet`.
    function approveRecovery(address wallet) external;

    /// @notice Completes recovery after the timelock has fully elapsed.
    function completeRecovery(address wallet) external;

    /// @notice Cancels the active recovery.
    function cancelRecovery(address wallet) external;

    /// @notice Current state of `wallet`'s recovery request.
    function stateOf(address wallet) external view returns (RecoveryState);
}
