// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GuardianRegistry} from "./GuardianRegistry.sol";
import {IGuardianRegistry} from "./interfaces/IGuardianRegistry.sol";
import {IKeymeshWallet} from "./interfaces/IKeymeshWallet.sol";
import {IRecoveryManager} from "./interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title RecoveryManager
/// @notice Guardian-quorum recovery with a mandatory per-wallet timelock.
/// @dev Phase 1.2 implementation of docs/protocol/recovery.md.
///
///      Trust model (single policy point):
///       - Bootstrap: the wallet's `manager` configures the initial guardian
///         set + quorum + timelock exactly once; this also retires its own
///         authority on the wallet. No manager backdoor remains afterwards.
///       - Guardians: initiate and approve recoveries for their own wallet
///         only. They cannot sign transactions, cancel, or move funds.
///       - Devices: initiate and cancel recoveries through their normal
///         signing authority (calls forwarded by KeymeshWallet.execute, so
///         msg.sender here is the wallet contract).
///       - finalizeRecovery is permissionless: it executes an already-approved,
///         timelock-expired request — authorization was complete before then.
///
///      State machine: None → Pending → QuorumReached → Executable → Executed,
///      with Pending/QuorumReached/Executable able to transition to Cancelled.
///      `QuorumReached → Executable` is materialized lazily when
///      block.timestamp >= executeAfter (inclusive boundary). Quorum and
///      timelock are snapshotted into the request at initiation, so later
///      configuration changes cannot weaken an in-flight recovery.
///
///      Storage notes:
///       - Requests are keyed by a global monotonically increasing id;
///         `_latestRecoveryId[wallet]` always points at the wallet's most
///         recent request (0 before the first one). Terminal requests keep
///         their record AND their id slot, so `statusOf` keeps reporting
///         Executed/Cancelled for auditability — a terminal status simply
///         blocks every transition until a NEW request is initiated under a
///         fresh id (stale approvals can therefore never revive one).
///       - Approvals use per-request mappings; no approval lists are stored,
///         so cancellation/finalization never iterate over guardians.
contract RecoveryManager is IRecoveryManager {
    struct RecoveryRequest {
        address wallet;
        address initiator;
        address replacedDevice; // address(0) = nothing to revoke (all devices lost)
        address newDevice;
        uint64 initiatedAt;
        uint64 executeAfter; // set when quorum reached; 0 while pending
        uint64 timelockSnapshot; // seconds; copied from config at initiation
        uint32 approvals;
        uint32 quorumSnapshot; // count of distinct guardian approvals required
        RecoveryStatus status;
    }

    /// @notice Minimum recovery timelock. Guarantees every takeover attempt
    ///         has at least this long as a public warning window.
    uint64 public constant MIN_TIMELOCK = 1 hours;

    /// @notice The single guardian-set storage module this contract controls.
    ///         Constructed (and owned) here so the pairing can never be
    ///         misconfigured.
    IGuardianRegistry public immutable guardianRegistry;

    uint256 private _nextRecoveryId;
    mapping(address wallet => uint256 recoveryId) private _latestRecoveryId;
    mapping(uint256 recoveryId => RecoveryRequest) private _requests;
    mapping(address wallet => uint256 quorum) private _quorum;
    mapping(address wallet => uint64 timelockSeconds) private _timelockSeconds;
    mapping(uint256 recoveryId => mapping(address guardian => bool)) private _approved;

    constructor() {
        guardianRegistry = new GuardianRegistry(address(this));
        _nextRecoveryId = 1; // id 0 reserved as "no active recovery"
    }

    // ---------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------

    modifier onlyWalletContract(address wallet) {
        if (msg.sender != wallet) revert KeymeshErrors.Unauthorized();
        _;
    }

    modifier onlyInitialized(address wallet) {
        if (!IKeymeshWallet(wallet).recoveryInitialized()) revert KeymeshErrors.NotInitialized();
        _;
    }

    // ---------------------------------------------------------------
    // Bootstrap (manager-only, exactly once per wallet)
    // ---------------------------------------------------------------

    function bootstrapRecoveryGovernance(
        address wallet,
        address[] calldata initialGuardians,
        uint256 quorum,
        uint64 timelockSeconds
    ) external {
        IKeymeshWallet walletContract = IKeymeshWallet(wallet);
        if (walletContract.manager() != msg.sender) revert KeymeshErrors.Unauthorized();
        if (walletContract.recoveryInitialized()) revert KeymeshErrors.AlreadyInitialized();

        _validateGuardianSetAndQuorum(initialGuardians, quorum);
        _validateTimelock(timelockSeconds);

        _quorum[wallet] = quorum;
        _timelockSeconds[wallet] = timelockSeconds;
        for (uint256 i = 0; i < initialGuardians.length; ++i) {
            guardianRegistry.addGuardian(wallet, initialGuardians[i]);
        }

        // Flips the wallet into guardian-governed mode and permanently retires
        // the bootstrap manager's device authority.
        walletContract.initializeRecoveryGovernance();

        emit GuardianSetAdded(wallet, initialGuardians, quorum);
        emit RecoveryGovernanceBootstrapped(wallet, msg.sender, quorum, timelockSeconds);
    }

    // ---------------------------------------------------------------
    // Guardian-set governance (device-signed through wallet.execute)
    // ---------------------------------------------------------------

    function addGuardian(address wallet, address guardian)
        external
        onlyWalletContract(wallet)
        onlyInitialized(wallet)
    {
        if (guardian == address(0)) revert KeymeshErrors.ZeroAddress();
        guardianRegistry.addGuardian(wallet, guardian);
    }

    function removeGuardian(address wallet, address guardian)
        external
        onlyWalletContract(wallet)
        onlyInitialized(wallet)
    {
        guardianRegistry.removeGuardian(wallet, guardian);
    }

    /// @notice Sets the quorum used by FUTURE recoveries; in-flight requests
    ///         keep their snapshot.
    function setQuorum(address wallet, uint256 quorum)
        external
        onlyWalletContract(wallet)
        onlyInitialized(wallet)
    {
        if (quorum == 0 || quorum > guardianRegistry.guardianCount(wallet)) {
            revert KeymeshErrors.InvalidQuorum(quorum, guardianRegistry.guardianCount(wallet));
        }
        _quorum[wallet] = quorum;
    }

    /// @notice Sets the timelock applied by FUTURE recoveries.
    function setRecoveryTimelock(address wallet, uint64 timelockSeconds)
        external
        onlyWalletContract(wallet)
        onlyInitialized(wallet)
    {
        _validateTimelock(timelockSeconds);
        _timelockSeconds[wallet] = timelockSeconds;
    }

    // ---------------------------------------------------------------
    // Recovery lifecycle
    // ---------------------------------------------------------------

    function initiateRecovery(address wallet, address replacedDevice, address newDevice) external {
        if (!IKeymeshWallet(wallet).recoveryInitialized()) {
            revert KeymeshErrors.NotInitialized();
        }

        // Authority: an active guardian of THIS wallet or an authorized
        // device of THIS wallet. Nobody else — not managers, not guardians
        // of other wallets.
        if (
            !guardianRegistry.isGuardian(wallet, msg.sender)
                && !IKeymeshWallet(wallet).isDeviceAuthorized(msg.sender)
        ) {
            revert NotGuardianOrDevice(msg.sender);
        }

        if (_hasLiveRequest(wallet)) {
            revert RecoveryAlreadyActive(_latestRecoveryId[wallet]);
        }
        if (newDevice == address(0)) revert InvalidReplacementDevice(newDevice);
        if (newDevice == replacedDevice) revert InvalidReplacementDevice(newDevice);
        if (IKeymeshWallet(wallet).isDeviceAuthorized(newDevice)) {
            revert InvalidReplacementDevice(newDevice);
        }
        if (
            replacedDevice != address(0)
                && !IKeymeshWallet(wallet).isDeviceAuthorized(replacedDevice)
        ) {
            revert InvalidReplacedDevice(replacedDevice);
        }

        uint256 quorum = _quorum[wallet];
        uint256 guardianCount = guardianRegistry.guardianCount(wallet);
        if (quorum > guardianCount) revert UnsatisfiableQuorum(quorum, guardianCount);

        uint256 recoveryId = _nextRecoveryId++;
        _requests[recoveryId] = RecoveryRequest({
            wallet: wallet,
            initiator: msg.sender,
            replacedDevice: replacedDevice,
            newDevice: newDevice,
            initiatedAt: uint64(block.timestamp),
            executeAfter: 0,
            timelockSnapshot: _timelockSeconds[wallet],
            approvals: 0,
            quorumSnapshot: uint32(quorum),
            status: RecoveryStatus.Pending
        });
        _latestRecoveryId[wallet] = recoveryId;

        emit RecoveryInitiated({
            recoveryId: recoveryId,
            wallet: wallet,
            initiator: msg.sender,
            replacedDevice: replacedDevice,
            newDevice: newDevice,
            quorum: quorum,
            initiatedAt: uint64(block.timestamp)
        });
    }

    function approveRecovery(address wallet) external {
        uint256 recoveryId = _latestRecoveryId[wallet];
        RecoveryRequest storage request = _requests[recoveryId];
        if (request.status != RecoveryStatus.Pending) {
            revert InvalidStateTransition(request.status, "approve");
        }
        if (!guardianRegistry.isGuardian(wallet, msg.sender)) {
            revert NotRegisteredGuardian(msg.sender);
        }
        if (_approved[recoveryId][msg.sender]) revert DuplicateApproval(msg.sender);

        _approved[recoveryId][msg.sender] = true;
        unchecked {
            request.approvals += 1;
        }
        emit RecoveryApproved(recoveryId, wallet, msg.sender, request.approvals);

        if (request.approvals >= request.quorumSnapshot) {
            request.status = RecoveryStatus.QuorumReached;
            request.executeAfter = uint64(block.timestamp) + request.timelockSnapshot;
            emit RecoveryTimelockStarted(recoveryId, wallet, request.executeAfter);
        }
    }

    function cancelRecovery(address wallet) external {
        // Only the wallet's currently authorized devices may cancel: the
        // device-holder security model must be able to stop a hostile
        // recovery, while a single compromised guardian cannot grief honest
        // ones by cancelling legitimate recoveries.
        if (!IKeymeshWallet(wallet).isDeviceAuthorized(msg.sender)) {
            revert KeymeshErrors.Unauthorized();
        }

        uint256 recoveryId = _latestRecoveryId[wallet];
        RecoveryRequest storage request = _requests[recoveryId];
        _refresh(request);
        if (
            request.status != RecoveryStatus.Pending
                && request.status != RecoveryStatus.QuorumReached
                && request.status != RecoveryStatus.Executable
        ) {
            revert InvalidStateTransition(request.status, "cancel");
        }

        request.status = RecoveryStatus.Cancelled;
        emit RecoveryCancelled(recoveryId, wallet, msg.sender);
    }

    function finalizeRecovery(address wallet) external {
        uint256 recoveryId = _latestRecoveryId[wallet];
        RecoveryRequest storage request = _requests[recoveryId];
        _refresh(request);
        if (request.status != RecoveryStatus.Executable) {
            if (
                request.status == RecoveryStatus.QuorumReached
                    && block.timestamp < request.executeAfter
            ) {
                revert TimelockNotElapsed(request.executeAfter, uint64(block.timestamp));
            }
            revert InvalidStateTransition(request.status, "finalize");
        }

        request.status = RecoveryStatus.Executed;

        // Atomic device replacement inside the wallet; any failure reverts
        // the whole finalization including the status write above.
        IKeymeshWallet(wallet).applyRecoveredDevice(request.replacedDevice, request.newDevice);

        emit RecoveryFinalized(recoveryId, wallet, request.newDevice, request.replacedDevice);
    }

    // ---------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------

    /// @notice Effective status of the wallet's active request. Promotes
    ///         QuorumReached to Executable once the timelock has elapsed
    ///         (inclusive boundary: now >= executeAfter).
    function statusOf(address wallet) external view returns (RecoveryStatus) {
        RecoveryRequest memory request = _requests[_latestRecoveryId[wallet]];
        return _effectiveStatus(request);
    }

    /// @notice Id of the wallet's most recent request (0 before the first).
    function latestRecoveryIdOf(address wallet) external view returns (uint256) {
        return _latestRecoveryId[wallet];
    }

    function quorumOf(address wallet) external view returns (uint256) {
        return _quorum[wallet];
    }

    function recoveryTimelockSeconds(address wallet) external view returns (uint64) {
        return _timelockSeconds[wallet];
    }

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
        )
    {
        RecoveryRequest memory request = _requests[recoveryId];
        return (
            request.wallet,
            request.initiator,
            request.replacedDevice,
            request.newDevice,
            request.initiatedAt,
            request.executeAfter,
            request.approvals,
            request.quorumSnapshot,
            _effectiveStatus(request)
        );
    }

    function hasApproved(uint256 recoveryId, address guardian) external view returns (bool) {
        return _approved[recoveryId][guardian];
    }

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    /// @dev Lazy state promotion: QuorumReached becomes Executable at and
    ///      after executeAfter (inclusive boundary, matching KeymeshWallet's
    ///      expiry rule of "valid while now <= deadline").
    function _effectiveStatus(RecoveryRequest memory request)
        private
        view
        returns (RecoveryStatus)
    {
        if (
            request.status == RecoveryStatus.QuorumReached
                && block.timestamp >= request.executeAfter
        ) {
            return RecoveryStatus.Executable;
        }
        return request.status;
    }

    function _refresh(RecoveryRequest storage request) private {
        if (
            request.status == RecoveryStatus.QuorumReached
                && block.timestamp >= request.executeAfter
        ) {
            request.status = RecoveryStatus.Executable;
        }
    }

    function _validateGuardianSetAndQuorum(address[] calldata guardians, uint256 quorum)
        private
        pure
    {
        if (guardians.length == 0) revert KeymeshErrors.InvalidGuardianSet();
        if (quorum == 0 || quorum > guardians.length) {
            revert KeymeshErrors.InvalidQuorum(quorum, guardians.length);
        }
        for (uint256 i = 0; i < guardians.length; ++i) {
            if (guardians[i] == address(0)) revert KeymeshErrors.ZeroAddress();
            for (uint256 j = i + 1; j < guardians.length; ++j) {
                if (guardians[i] == guardians[j]) revert KeymeshErrors.InvalidGuardianSet();
            }
        }
    }

    function _validateTimelock(uint64 timelockSeconds) private pure {
        if (timelockSeconds < MIN_TIMELOCK) {
            revert KeymeshErrors.TimelockTooShort({
                provided: timelockSeconds, minimum: MIN_TIMELOCK
            });
        }
    }

    /// @dev A request is live while its status is Pending, QuorumReached, or
    ///      Executable; Executed/Cancelled/None allow new initiations.
    function _hasLiveRequest(address wallet) private view returns (bool) {
        RecoveryStatus status = _effectiveStatus(_requests[_latestRecoveryId[wallet]]);
        return status == RecoveryStatus.Pending || status == RecoveryStatus.QuorumReached
            || status == RecoveryStatus.Executable;
    }
}

