// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Errors shared by KeyMesh contracts.
library KeymeshErrors {
    /// @dev The caller is not authorized for this operation.
    error Unauthorized();

    /// @dev A zero address was supplied where one is not allowed.
    error ZeroAddress();

    /// @dev The operation is not implemented yet.
    ///      Skeleton contracts revert with this instead of pretending to work.
    error NotImplemented();

    // ---------------------------------------------------------------
    // Recovery governance (Phase 1.2)
    // ---------------------------------------------------------------

    /// @dev Recovery governance for this wallet was already initialized;
    ///      bootstrap can happen exactly once.
    error AlreadyInitialized();

    /// @dev Recovery governance must be initialized before this operation.
    error NotInitialized();

    /// @dev Quorum must be greater than zero and at most the guardian count.
    error InvalidQuorum(uint256 quorum, uint256 guardianCount);

    /// @dev Timelock is shorter than the protocol minimum.
    error TimelockTooShort(uint64 provided, uint64 minimum);

    /// @dev The guardian list is empty or contains duplicates/zero addresses.
    error InvalidGuardianSet();
}
