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
}
