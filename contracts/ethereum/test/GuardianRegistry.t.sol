// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {IGuardianRegistry} from "../src/interfaces/IGuardianRegistry.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @dev Tests run as the wallet address via `vm.prank(wallet)` because the
///      prototype restricts guardian mutations to the wallet itself.
contract GuardianRegistryTest is Test {
    GuardianRegistry internal registry;

    address internal constant WALLET = address(0xA11CE);
    address internal constant GUARDIAN1 = address(0x1);
    address internal constant GUARDIAN2 = address(0x2);
    address internal constant GUARDIAN3 = address(0x3);

    function setUp() public {
        registry = new GuardianRegistry();
    }

    function test_AddGuardianAccumulatesWeight() public {
        vm.prank(WALLET);
        registry.addGuardian(WALLET, GUARDIAN1, 2);
        vm.prank(WALLET);
        registry.addGuardian(WALLET, GUARDIAN2, 1);

        assertEq(registry.totalWeight(WALLET), 3);
        assertEq(registry.guardianCount(WALLET), 2);
        assertTrue(registry.isGuardian(WALLET, GUARDIAN1));
        assertEq(registry.weightOf(WALLET, GUARDIAN1), 2);
    }

    function test_RemoveGuardianReducesWeight() public {
        vm.startPrank(WALLET);
        registry.addGuardian(WALLET, GUARDIAN1, 2);
        registry.addGuardian(WALLET, GUARDIAN2, 1);
        registry.removeGuardian(WALLET, GUARDIAN1);
        vm.stopPrank();

        assertEq(registry.totalWeight(WALLET), 1);
        assertEq(registry.guardianCount(WALLET), 1);
        assertFalse(registry.isGuardian(WALLET, GUARDIAN1));
        assertEq(registry.weightOf(WALLET, GUARDIAN1), 0);
    }

    function test_NonWalletCannotModify() public {
        vm.prank(GUARDIAN1);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        registry.addGuardian(WALLET, GUARDIAN1, 1);

        vm.prank(GUARDIAN1);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        registry.removeGuardian(WALLET, GUARDIAN1);
    }

    function test_ZeroWeightRejected() public {
        vm.prank(WALLET);
        vm.expectRevert(IGuardianRegistry.InvalidWeight.selector);
        registry.addGuardian(WALLET, GUARDIAN1, 0);
    }

    function test_DoubleAddAndRemoveOfInactiveRevert() public {
        vm.startPrank(WALLET);
        registry.addGuardian(WALLET, GUARDIAN1, 1);
        vm.expectRevert(abi.encodeWithSelector(IGuardianRegistry.GuardianAlreadyActive.selector, GUARDIAN1));
        registry.addGuardian(WALLET, GUARDIAN1, 1);

        registry.removeGuardian(WALLET, GUARDIAN1);
        vm.expectRevert(abi.encodeWithSelector(IGuardianRegistry.GuardianNotActive.selector, GUARDIAN1));
        registry.removeGuardian(WALLET, GUARDIAN1);
        vm.stopPrank();
    }

    function test_ZeroAddressGuardianRejected() public {
        vm.prank(WALLET);
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        registry.addGuardian(WALLET, address(0), 1);
    }
}
