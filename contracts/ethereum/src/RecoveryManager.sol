// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuardianRegistry} from "./interfaces/IGuardianRegistry.sol";
import {IRecoveryManager} from "./interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title RecoveryManager
/// @notice Guardian-quorum recovery with a mandatory timelock per wallet.
/// @dev PROTOTYPE reference implementation of the state machine documented in
///      docs/protocol/recovery.md.
///
///      Deliberate simplifications (TODO phase-1):
///       - `initiateRecovery` is permissionless; the wallet contract will be
///         the only authorized initiator once device authorization exists.
///       - One active recovery per wallet (sufficient for the initial model).
contract RecoveryManager is IRecoveryManager {
    struct RecoveryRequest {
        address newDevice;
        uint256 approvalsWeight;
        uint256 requiredWeight;
        uint64 timelockEndsAt;
        RecoveryState state;
    }

    /// @notice Minimum recovery timelock. Shorter windows are rejected to keep
    /// the "guardians collude" attack at least a week of public warning time.
    uint64 public constant MIN_TIMELOCK = 7 days;

    IGuardianRegistry public immutable guardianRegistry;

    mapping(address wallet => RecoveryRequest) private _requests;
    mapping(address wallet => mapping(address guardian => bool)) private _hasApproved;

    constructor(IGuardianRegistry registry) {
        if (address(registry) == address(0)) revert KeymeshErrors.ZeroAddress();
        guardianRegistry = registry;
    }

    function initiateRecovery(
        address wallet,
        address newDevice,
        uint256 requiredWeight,
        uint64 timelockSeconds
    ) external {
        if (wallet == address(0) || newDevice == address(0)) revert KeymeshErrors.ZeroAddress();
        // TODO(phase-1): restrict to the wallet contract / owner device.
        if (_requests[wallet].state != RecoveryState.None && !_isTerminal(_requests[wallet].state)) {
            revert RecoveryAlreadyActive();
        }
        if (timelockSeconds < MIN_TIMELOCK) revert TimelockTooShort();

        _requests[wallet] = RecoveryRequest({
            newDevice: newDevice,
            approvalsWeight: 0,
            requiredWeight: requiredWeight,
            timelockEndsAt: 0,
            state: RecoveryState.Pending
        });

        emit RecoveryInitiated(wallet, newDevice, requiredWeight);
    }

    function approveRecovery(address wallet) external {
        RecoveryRequest storage request = _requests[wallet];
        if (request.state != RecoveryState.Pending) revert NoActiveRecovery();
        address guardian = msg.sender;
        if (!guardianRegistry.isGuardian(wallet, guardian)) {
            revert NotRegisteredGuardian(guardian);
        }
        if (_hasApproved[wallet][guardian]) revert DuplicateApproval(guardian);

        uint256 weight = guardianRegistry.weightOf(wallet, guardian);
        request.approvalsWeight += weight;
        _hasApproved[wallet][guardian] = true;

        emit RecoveryApproved(wallet, guardian, request.approvalsWeight);

        if (request.approvalsWeight >= request.requiredWeight) {
            request.state = RecoveryState.TimelockActive;
            request.timelockEndsAt = uint64(block.timestamp) + _timelockSeconds(wallet);
            emit RecoveryTimelockStarted(wallet, request.timelockEndsAt);
        }
    }

    function completeRecovery(address wallet) external {
        RecoveryRequest storage request = _requests[wallet];
        if (request.state != RecoveryState.TimelockActive) revert NoActiveRecovery();
        if (block.timestamp < request.timelockEndsAt) {
            revert TimelockNotElapsed(request.timelockEndsAt, block.timestamp);
        }

        request.state = RecoveryState.Completed;
        emit RecoveryCompleted(wallet, request.newDevice);
        // TODO(phase-1): call into KeymeshWallet to authorize `newDevice`.
    }

    function cancelRecovery(address wallet) external {
        RecoveryRequest storage request = _requests[wallet];
        if (_isTerminal(request.state)) revert NoActiveRecovery();
        // TODO(phase-1): allow wallet/owner devices and guardians to cancel;
        // prototype permits any caller so tests can exercise the transition.
        delete _hasApproved[wallet];
        request.state = RecoveryState.Cancelled;
        emit RecoveryCancelled(wallet);
    }

    function stateOf(address wallet) external view returns (RecoveryState) {
        return _requests[wallet].state;
    }

    function approvalsWeightOf(address wallet) external view returns (uint256) {
        return _requests[wallet].approvalsWeight;
    }

    function timelockEndsAt(address wallet) external view returns (uint64) {
        return _requests[wallet].timelockEndsAt;
    }

    /// @notice Prototype timelock duration source: fixed at MIN_TIMELOCK until
    /// PolicyManager integration lands (TODO phase-1).
    function _timelockSeconds(address) internal view returns (uint64) {
        return MIN_TIMELOCK;
    }

    function _isTerminal(RecoveryState state) internal pure returns (bool) {
        return state == RecoveryState.Completed || state == RecoveryState.Cancelled;
    }
}
