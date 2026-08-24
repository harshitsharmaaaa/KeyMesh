// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IKeymeshWallet
/// @notice Device-authorized KeyMesh wallet: signature-verified execution plus
///         a guardian-governed device-replacement entry point.
/// @dev Phase 1.2 authority model:
///
///      Normal transactions : registered-device ECDSA over KEYMESH_TX_V1.
///      Device-set changes  : `recoveryManager` only (guardian quorum +
///                            timelock), or the bootstrap manager BEFORE
///                            recovery governance is initialized.
///
///      The manager is a BOOTSTRAP-ONLY role. Once `initializeRecoveryGovernance`
///      has been called by the RecoveryManager, the manager has no authority
///      whatsoever (see `ManagerAuthorityRetired`). Guardians never sign
///      normal transactions; devices never approve recoveries.
interface IKeymeshWallet {
    event DeviceRegistered(address indexed device, uint64 registeredAt);
    event DeviceRevoked(address indexed device, uint64 revokedAt);
    event RecoveryGovernanceInitialized(uint64 initializedAt);
    event TransactionExecuted(
        uint256 indexed nonce, address indexed device, address indexed to, uint256 value, bytes data
    );

    // --- device management ---
    error ZeroAddress();
    error NotDeviceManager(address caller);
    error AlreadyRegistered(address device);
    error NotRegistered(address device);
    error LastDeviceRemoval();

    // --- bootstrap / recovery wiring ---
    /// @dev The bootstrap manager attempted an operation after recovery
    ///      governance was initialized; the role is retired at that point.
    error ManagerAuthorityRetired(address manager);
    /// @dev Caller is not this wallet's designated RecoveryManager.
    error NotRecoveryManager(address caller);

    // --- execution / validation ---
    error WrongWallet(address provided);
    error WrongChain(uint256 provided);
    error InvalidNonce(uint256 expected, uint256 provided);
    error TransactionExpired(uint256 expiry, uint256 nowTs);
    error UnauthorizedDevice(address signer);
    error ExecutionFailed(bytes returnData);

    /// @notice Address allowed to call {applyRecoveredDevice} and
    ///         {initializeRecoveryGovernance} (the RecoveryManager contract).
    function recoveryManager() external view returns (address);

    /// @notice Transaction authorization policy layer consulted by execute();
    ///         address(0) disables the policy layer (Phase 1.1 semantics).
    function policyManager() external view returns (address);

    /// @notice True once guardian recovery governance has been bootstrapped;
    ///         afterwards the bootstrap manager holds no authority.
    function recoveryInitialized() external view returns (bool);

    /// @notice Bootstrap-only transitional account; inert after initialization.
    function manager() external view returns (address);

    /// @notice Registers `device`. Callable ONLY by the bootstrap manager and
    ///         ONLY before recovery governance is initialized.
    function registerDevice(address device) external;

    /// @notice Revokes `device`. Allowed for the bootstrap manager before
    ///         initialization, or by the device itself at any time.
    function revokeDevice(address device) external;

    /// @notice Applies a finalized guardian recovery atomically:
    ///         authorize `newDevice`, then revoke `replacedDevice` when it is
    ///         not the zero address. Only the RecoveryManager may call.
    /// @param replacedDevice Device to revoke, or address(0) when every
    ///        previous device was already lost (pure addition).
    /// @param newDevice Replacement device to authorize.
    function applyRecoveredDevice(address replacedDevice, address newDevice) external;

    /// @notice Marks recovery governance live; retires the bootstrap manager.
    ///         Only the RecoveryManager may call (during bootstrap).
    function initializeRecoveryGovernance() external;

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
