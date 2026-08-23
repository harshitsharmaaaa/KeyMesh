// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuardianRegistry} from "./interfaces/IGuardianRegistry.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title GuardianRegistry
/// @notice Tracks per-wallet guardian sets with weighted votes.
/// @dev PROTOTYPE. Access control currently trusts `msg.sender == wallet`
///      (the wallet contract is expected to be the only caller). Replace with
///      explicit wallet-contract allowlisting once KeymeshWallet exposes an
///      authorization surface (TODO phase-1).
contract GuardianRegistry is IGuardianRegistry {
    struct GuardianInfo {
        uint96 weight;
        bool active;
    }

    mapping(address wallet => mapping(address guardian => GuardianInfo)) private _guardians;
    mapping(address wallet => uint256) private _totalWeight;
    mapping(address wallet => uint256) private _guardianCount;

    function addGuardian(address wallet, address guardian, uint96 weight) external {
        if (msg.sender != wallet) revert KeymeshErrors.Unauthorized();
        if (guardian == address(0) || wallet == address(0)) revert KeymeshErrors.ZeroAddress();
        if (weight == 0) revert InvalidWeight();
        GuardianInfo storage info = _guardians[wallet][guardian];
        if (info.active) revert GuardianAlreadyActive(guardian);

        info.weight = weight;
        info.active = true;
        _totalWeight[wallet] += weight;
        _guardianCount[wallet] += 1;

        emit GuardianAdded(wallet, guardian, weight);
    }

    function removeGuardian(address wallet, address guardian) external {
        if (msg.sender != wallet) revert KeymeshErrors.Unauthorized();
        GuardianInfo storage info = _guardians[wallet][guardian];
        if (!info.active) revert GuardianNotActive(guardian);

        _totalWeight[wallet] -= info.weight;
        _guardianCount[wallet] -= 1;
        delete _guardians[wallet][guardian];

        emit GuardianRemoved(wallet, guardian);
    }

    function isGuardian(address wallet, address guardian) external view returns (bool) {
        return _guardians[wallet][guardian].active;
    }

    function weightOf(address wallet, address guardian) external view returns (uint256) {
        GuardianInfo storage info = _guardians[wallet][guardian];
        return info.active ? info.weight : 0;
    }

    function totalWeight(address wallet) external view returns (uint256) {
        return _totalWeight[wallet];
    }

    function guardianCount(address wallet) external view returns (uint256) {
        return _guardianCount[wallet];
    }
}
