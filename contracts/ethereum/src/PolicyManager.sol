// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPolicyManager} from "./interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title PolicyManager
/// @notice Stores per-wallet transaction authorization policies.
/// @dev PROTOTYPE. Policies are set by the wallet itself; thresholds are plain
///      weights resolved against GuardianRegistry totals by callers.
contract PolicyManager is IPolicyManager {
    mapping(address wallet => Policy) private _policies;

    function setPolicy(address wallet, Policy calldata policy) external {
        if (msg.sender != wallet) revert KeymeshErrors.Unauthorized();
        if (wallet == address(0)) revert KeymeshErrors.ZeroAddress();
        // A usable policy must always authorize normal transfers with a
        // positive weight and never allow a zero recovery quorum.
        if (policy.normalWeight == 0) revert InvalidPolicy("normalWeight");
        if (policy.recoveryWeight == 0) revert InvalidPolicy("recoveryWeight");

        _policies[wallet] = policy;
        emit PolicySet(wallet, policy);
    }

    function policyOf(address wallet) external view returns (Policy memory) {
        return _policies[wallet];
    }

    function requiredWeight(address wallet, TxClass txClass) external view returns (uint256) {
        Policy storage p = _policies[wallet];
        if (txClass == TxClass.Normal) return p.normalWeight;
        if (txClass == TxClass.HighValue) return p.highValueWeight;
        if (txClass == TxClass.Recovery) return p.recoveryWeight;
        // GuardianManagement / PolicyUpdate reuse the high-value quorum until
        // dedicated rules exist (TODO phase-1).
        return p.highValueWeight;
    }
}
