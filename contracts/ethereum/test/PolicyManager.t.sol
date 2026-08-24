// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

contract PolicyManagerTest is Test {
    PolicyManager internal policyManager;
    address internal constant WALLET = address(0xA11CE);

    function setUp() public {
        policyManager = new PolicyManager();
    }

    function _policy() internal pure returns (IPolicyManager.Policy memory p) {
        p = IPolicyManager.Policy({
            normalWeight: 1,
            highValueWeight: 2,
            highValueWeiBoundary: 1 ether,
            recoveryWeight: 3,
            recoveryTimelock: 7 days
        });
    }

    function test_SetAndGetPolicy() public {
        vm.prank(WALLET);
        policyManager.setPolicy(WALLET, _policy());

        IPolicyManager.Policy memory stored = policyManager.policyOf(WALLET);
        assertEq(stored.normalWeight, 1);
        assertEq(stored.highValueWeight, 2);
        assertEq(stored.recoveryTimelock, 7 days);

        assertEq(policyManager.requiredWeight(WALLET, IPolicyManager.TxClass.Normal), 1);
        assertEq(policyManager.requiredWeight(WALLET, IPolicyManager.TxClass.Recovery), 3);
    }

    function test_OnlyWalletCanSetOwnPolicy() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        policyManager.setPolicy(WALLET, _policy());
    }

    function test_ZeroThresholdsRejected() public {
        IPolicyManager.Policy memory bad = _policy();
        bad.normalWeight = 0;
        vm.prank(WALLET);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.InvalidPolicy.selector, "normalWeight")
        );
        policyManager.setPolicy(WALLET, bad);

        IPolicyManager.Policy memory bad2 = _policy();
        bad2.recoveryWeight = 0;
        vm.prank(WALLET);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.InvalidPolicy.selector, "recoveryWeight")
        );
        policyManager.setPolicy(WALLET, bad2);
    }
}
