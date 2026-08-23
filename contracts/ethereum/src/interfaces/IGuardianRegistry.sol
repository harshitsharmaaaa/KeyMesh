// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IGuardianRegistry
/// @notice Tracks guardians and their weights per KeyMesh wallet.
interface IGuardianRegistry {
    event GuardianAdded(address indexed wallet, address indexed guardian, uint96 weight);
    event GuardianRemoved(address indexed wallet, address indexed guardian);

    error GuardianAlreadyActive(address guardian);
    error GuardianNotActive(address guardian);
    error InvalidWeight();

    /// @notice Registers `guardian` for `wallet` with a weighted vote.
    /// @dev Only the wallet contract itself may modify its guardian set.
    function addGuardian(address wallet, address guardian, uint96 weight) external;

    /// @notice Removes an active guardian from `wallet`.
    function removeGuardian(address wallet, address guardian) external;

    /// @notice True when `guardian` is an active guardian of `wallet`.
    function isGuardian(address wallet, address guardian) external view returns (bool);

    /// @notice Current weight of `guardian` within `wallet`'s set (0 if inactive).
    function weightOf(address wallet, address guardian) external view returns (uint256);

    /// @notice Sum of active guardian weights for `wallet`.
    function totalWeight(address wallet) external view returns (uint256);

    /// @notice Number of active guardians for `wallet`.
    function guardianCount(address wallet) external view returns (uint256);
}
