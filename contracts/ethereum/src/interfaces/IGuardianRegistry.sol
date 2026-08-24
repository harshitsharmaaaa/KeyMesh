// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IGuardianRegistry
/// @notice Tracks the set of active guardians per KeyMesh wallet.
/// @dev Phase 1.2: guardians are unweighted (one guardian = one approval).
///      State mutations are restricted to the owning RecoveryManager, which is
///      the single policy enforcement point (bootstrap by the wallet manager,
///      then device-signed management through KeymeshWallet.execute).
interface IGuardianRegistry {
    event GuardianAdded(address indexed wallet, address indexed guardian);
    event GuardianRemoved(address indexed wallet, address indexed guardian);

    /// @dev `guardian` is not an active guardian of `wallet`.
    error GuardianNotActive(address wallet, address guardian);

    /// @dev `guardian` already is an active guardian of `wallet`.
    error GuardianAlreadyActive(address wallet, address guardian);

    /// @dev Caller is not the owning RecoveryManager.
    error NotRecoveryManager(address caller);

    /// @notice Registers `guardian` for `wallet`. RecoveryManager only.
    function addGuardian(address wallet, address guardian) external;

    /// @notice Removes an active guardian from `wallet`. RecoveryManager only.
    function removeGuardian(address wallet, address guardian) external;

    /// @notice True when `guardian` is an active guardian of `wallet`.
    function isGuardian(address wallet, address guardian) external view returns (bool);

    /// @notice Number of active guardians for `wallet`.
    function guardianCount(address wallet) external view returns (uint256);

    /// @notice Active guardians of `wallet` in registration order.
    ///         Bounded iteration in a VIEW only; never used inside a
    ///         security-critical transaction path.
    function getGuardians(address wallet) external view returns (address[] memory);
}
