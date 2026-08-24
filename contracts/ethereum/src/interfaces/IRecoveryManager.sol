// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuardianRegistry} from "./IGuardianRegistry.sol";

/// @title IRecoveryManager
/// @notice Guardian-quorum recovery with a mandatory per-wallet timelock.
/// @dev Phase 1.2 recovery state machine (explicit, auditable):
///
///       None ──initiate──────────────► Pending
///       Pending ──quorum reached──────► QuorumReached   (executeAfter set)
///       QuorumReached ──timelock ok───► Executable      (lazy promotion)
///       Executable ──finalize─────────► Executed        (terminal)
///       Pending/QuorumReached/Executable ──cancel─────► Cancelled (terminal)
///
///      Authority model:
///       - bootstrap : wallet's bootstrap manager, exactly once, pre-init.
///       - guardians : initiate + approve only (never sign transactions,
///                     never cancel, never move funds).
///       - devices   : initiate + cancel via their normal signing authority.
///       - finalize  : permissionless execution of an already-approved,
///                     timelock-expired recovery.
interface IRecoveryManager {
    /// Explicit lifecycle states; `Executable` is materialized lazily from
    /// QuorumReached once block.timestamp >= executeAfter.
    enum RecoveryStatus {
        None,
        Pending,
        QuorumReached,
        Executable,
        Executed,
        Cancelled
    }

    event GuardianSetAdded(address indexed wallet, address[] guardians, uint256 quorum);
    event RecoveryGovernanceBootstrapped(
        address indexed wallet,
        address indexed bootstrappedBy,
        uint256 quorum,
        uint64 timelockSeconds
    );
    event RecoveryInitiated(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed initiator,
        address replacedDevice,
        address newDevice,
        uint256 quorum,
        uint64 initiatedAt
    );
    event RecoveryApproved(
        uint256 indexed recoveryId,
        address indexed wallet,
        address indexed guardian,
        uint256 approvalCount
    );
    event RecoveryTimelockStarted(
        uint256 indexed recoveryId, address indexed wallet, uint64 executeAfter
    );
    event RecoveryCancelled(uint256 indexed recoveryId, address indexed wallet, address indexed by);
    event RecoveryFinalized(
        uint256 indexed recoveryId,
        address indexed wallet,
        address newDevice,
        address replacedDevice
    );

    // --- configuration errors ---
    error RecoveryAlreadyActive(uint256 activeRecoveryId);
    error NoActiveRecovery(address wallet);
    error InvalidReplacementDevice(address newDevice);
    error InvalidReplacedDevice(address replacedDevice);
    error UnsatisfiableQuorum(uint256 quorum, uint256 guardianCount);

    // --- initiation authority ---
    error NotGuardianOrDevice(address caller);

    // --- approval errors ---
    error NotRegisteredGuardian(address guardian);
    error DuplicateApproval(address guardian);
    error InvalidStateTransition(RecoveryStatus from, string attempted);

    // --- timelock ---
    error TimelockNotElapsed(uint64 executeAfter, uint64 nowTs);

    /// @notice Minimum allowed recovery timelock for any wallet.
    function MIN_TIMELOCK() external view returns (uint64);

    function guardianRegistry() external view returns (IGuardianRegistry);

    // --- bootstrap (manager-only, once) ---
    /// @notice Sets the initial guardian set, quorum, and timelock for
    ///         `wallet`, then marks its recovery governance initialized.
    function bootstrapRecoveryGovernance(
        address wallet,
        address[] calldata initialGuardians,
        uint256 quorum,
        uint64 timelockSeconds
    ) external;

    // --- device-signed governance (msg.sender == wallet contract) ---
    function addGuardian(address wallet, address guardian) external;
    function removeGuardian(address wallet, address guardian) external;
    function setQuorum(address wallet, uint256 quorum) external;
    function setRecoveryTimelock(address wallet, uint64 timelockSeconds) external;

    // --- recovery lifecycle ---
    /// @notice Opens a recovery replacing `replacedDevice` with `newDevice`.
    ///         Caller must be an active guardian or an authorized device of
    ///         `wallet`. Creating the request never changes the device set.
    function initiateRecovery(address wallet, address replacedDevice, address newDevice) external;

    /// @notice Records the calling guardian's approval (once per recovery).
    function approveRecovery(address wallet) external;

    /// @notice Cancels the active recovery; authorized devices only.
    function cancelRecovery(address wallet) external;

    /// @notice Executes a finalized recovery: authorize new device, revoke the
    ///         replaced device atomically on the wallet. Permissionless.
    function finalizeRecovery(address wallet) external;

    // --- views ---
    function statusOf(address wallet) external view returns (RecoveryStatus);
    function latestRecoveryIdOf(address wallet) external view returns (uint256);
    function quorumOf(address wallet) external view returns (uint256);
    function recoveryTimelockSeconds(address wallet) external view returns (uint64);
    function requestById(uint256 recoveryId)
        external
        view
        returns (
            address wallet,
            address initiator,
            address replacedDevice,
            address newDevice,
            uint64 initiatedAt,
            uint64 executeAfter,
            uint256 approvals,
            uint256 quorumSnapshot,
            RecoveryStatus status
        );
    function hasApproved(uint256 recoveryId, address guardian) external view returns (bool);
}
