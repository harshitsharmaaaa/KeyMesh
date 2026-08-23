// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IKeymeshWallet
/// @notice Minimal wallet surface for the KeyMesh protocol.
/// @dev SKELETON — Phase 1 implements device/threshold-authorized execution.
///      The current skeleton deliberately cannot move funds.
interface IKeymeshWallet {
    event DeviceAuthorized(address indexed device, uint64 authorizedAt);
    event DeviceRevoked(address indexed device, uint64 revokedAt);
    event WalletCreated(address indexed owner);

    error ExecutionNotYetImplemented();
    error AlreadyAuthorized(address device);
    error NotAuthorized(address device);

    /// @notice Authorizes a new device (public key account) on this wallet.
    function authorizeDevice(address device) external;

    /// @notice Revokes an authorized device immediately.
    function revokeDevice(address device) external;

    /// @notice Returns true when `device` is currently authorized.
    function isDeviceAuthorized(address device) external view returns (bool);

    /// @notice Executes a call from the wallet once the policy engine and
    ///         signature aggregation are implemented.
    /// @dev    Intentionally unimplemented in this skeleton; always reverts.
    function execute(address target, uint256 value, bytes calldata data) external;
}
