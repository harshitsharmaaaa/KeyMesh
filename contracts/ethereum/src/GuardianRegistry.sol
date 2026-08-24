// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuardianRegistry} from "./interfaces/IGuardianRegistry.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title GuardianRegistry
/// @notice Tracks the set of active guardians per KeyMesh wallet.
/// @dev Pure storage module: ALL policy (who may add/remove, bootstrap rules,
///      quorum math) lives in the owning RecoveryManager, which is the only
///      account allowed to mutate state. Guardians are unweighted — recovery
///      quorum counts distinct active guardians, one approval each.
contract GuardianRegistry is IGuardianRegistry {
    /// @dev The single authorized mutator (set at construction).
    address public immutable recoveryManager;

    mapping(address wallet => mapping(address guardian => bool)) private _active;
    // Registration-order tracking so views can enumerate guardians without
    // events. Mutations use swap-and-pop; view-only iteration.
    mapping(address wallet => address[]) private _guardianList;
    mapping(address wallet => uint256) private _guardianCount;

    constructor(address recoveryManager_) {
        if (recoveryManager_ == address(0)) revert KeymeshErrors.ZeroAddress();
        recoveryManager = recoveryManager_;
    }

    modifier onlyRecoveryManager() {
        if (msg.sender != recoveryManager) revert NotRecoveryManager(msg.sender);
        _;
    }

    function addGuardian(address wallet, address guardian) external onlyRecoveryManager {
        if (wallet == address(0) || guardian == address(0)) revert KeymeshErrors.ZeroAddress();
        if (_active[wallet][guardian]) revert GuardianAlreadyActive(wallet, guardian);

        _active[wallet][guardian] = true;
        _guardianList[wallet].push(guardian);
        _guardianCount[wallet] += 1;

        emit GuardianAdded(wallet, guardian);
    }

    function removeGuardian(address wallet, address guardian) external onlyRecoveryManager {
        if (!_active[wallet][guardian]) revert GuardianNotActive(wallet, guardian);

        _active[wallet][guardian] = false;
        _removeFromList(wallet, guardian);
        _guardianCount[wallet] -= 1;

        emit GuardianRemoved(wallet, guardian);
    }

    function isGuardian(address wallet, address guardian) external view returns (bool) {
        return _active[wallet][guardian];
    }

    function guardianCount(address wallet) external view returns (uint256) {
        return _guardianCount[wallet];
    }

    function getGuardians(address wallet) external view returns (address[] memory) {
        return _guardianList[wallet];
    }

    /// @dev Swap-and-pop keeps removal O(1); order of remaining guardians is
    ///      not a security property.
    function _removeFromList(address wallet, address guardian) private {
        address[] storage list = _guardianList[wallet];
        uint256 length = list.length;
        for (uint256 i = 0; i < length; ++i) {
            if (list[i] == guardian) {
                list[i] = list[length - 1];
                list.pop();
                return;
            }
        }
    }
}
