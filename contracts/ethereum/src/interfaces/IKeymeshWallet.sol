// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IKeymeshWallet
/// @notice Device-authorized KeyMesh wallet: signature-verified execution.
/// @dev Phase 1.1 — single-device ECDSA authorization over the canonical
///      KEYMESH_TX_V1 digest. The signer set abstraction (mapping of devices)
///      is designed to admit threshold/TSS signers in a later phase without
///      changing execute().
interface IKeymeshWallet {
    event DeviceRegistered(address indexed device, uint64 registeredAt);
    event DeviceRevoked(address indexed device, uint64 revokedAt);
    event TransactionExecuted(
        uint256 indexed nonce,
        address indexed device,
        address indexed to,
        uint256 value,
        bytes data
    );

    // --- device management ---
    error ZeroAddress();
    error NotDeviceManager(address caller);
    error AlreadyRegistered(address device);
    error NotRegistered(address device);
    error LastDeviceRemoval();

    // --- execution / validation ---
    error WrongWallet(address provided);
    error WrongChain(uint256 provided);
    error InvalidNonce(uint256 expected, uint256 provided);
    error TransactionExpired(uint256 expiry, uint256 nowTs);
    error UnauthorizedDevice(address signer);
    error ExecutionFailed(bytes returnData);

    /// @notice Registers `device`. Phase 1: only the wallet manager may call.
    function registerDevice(address device) external;

    /// @notice Revokes `device`. Allowed for the manager or the device itself.
    function revokeDevice(address device) external;

    /// @notice True when `device` can currently authorize transactions.
    function isDeviceAuthorized(address device) external view returns (bool);

    /// @notice Number of currently registered devices.
    function deviceCount() external view returns (uint256);

    /// @notice Next expected transaction nonce (replay protection).
    function getNonce() external view returns (uint256);

    /// @notice Digest the contract will verify for these fields; mirrors the
    ///         canonical encoding used by device signers.
    function transactionDigest(
        address wallet,
        uint256 chainId,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 expiry
    ) external view returns (bytes32);

    /// @notice Executes `call` to `to` with `value`, authorized by an active
    ///         device's ECDSA signature over the canonical digest.
    /// @param wallet Must equal this contract (explicit domain binding).
    /// @param chainId Must equal the live chain id (cross-chain replay guard).
    /// @param nonce Must equal the next expected nonce.
    /// @param expiry Unix seconds; valid while block.timestamp <= expiry.
    function execute(
        address wallet,
        uint256 chainId,
        address to,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        uint256 expiry,
        bytes calldata signature
    ) external;
}
