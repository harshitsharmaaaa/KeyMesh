// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {IGuardianRegistry} from "../src/interfaces/IGuardianRegistry.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @notice Phase 1.2 GuardianRegistry storage semantics. The owning
/// RecoveryManager delegates mutations here; policy lives there and is tested
/// in RecoveryManager.t.sol, so this suite exercises the storage contract
/// directly against its owner.
contract GuardianRegistryTest is Test {
    GuardianRegistry internal registry;

    address internal constant WALLET = address(0xA11CE);
    address internal constant WALLET_B = address(0xB002);
    address internal constant GUARDIAN1 = address(0x0001);
    address internal constant GUARDIAN2 = address(0x0002);
    address internal constant GUARDIAN3 = address(0x0003);

    function setUp() public {
        // The test contract plays the RecoveryManager role (the only mutator).
        registry = new GuardianRegistry(address(this));
    }

    // ---------------------------------------------------------------
    // construction / access control
    // ---------------------------------------------------------------

    function test_ZeroRecoveryManagerRejected() public {
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        new GuardianRegistry(address(0));
    }

    function test_OwnerIsRecordedAndReadable() public view {
        assertEq(registry.recoveryManager(), address(this));
    }

    function test_NonOwnerCannotAddOrRemove() public {
        vm.startPrank(GUARDIAN1);
        vm.expectRevert(
            abi.encodeWithSelector(IGuardianRegistry.NotRecoveryManager.selector, GUARDIAN1)
        );
        registry.addGuardian(WALLET, GUARDIAN1);

        vm.expectRevert(
            abi.encodeWithSelector(IGuardianRegistry.NotRecoveryManager.selector, GUARDIAN1)
        );
        registry.removeGuardian(WALLET, GUARDIAN1);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------
    // add / remove semantics
    // ---------------------------------------------------------------

    function test_AddAndEnumerateGuardians() public {
        registry.addGuardian(WALLET, GUARDIAN1);
        registry.addGuardian(WALLET, GUARDIAN2);
        registry.addGuardian(WALLET, GUARDIAN3);

        assertTrue(registry.isGuardian(WALLET, GUARDIAN1));
        assertTrue(registry.isGuardian(WALLET, GUARDIAN2));
        assertTrue(registry.isGuardian(WALLET, GUARDIAN3));
        assertFalse(registry.isGuardian(WALLET, address(0x9999)));
        assertEq(registry.guardianCount(WALLET), 3);

        address[] memory listed = registry.getGuardians(WALLET);
        assertEq(listed.length, 3);
        assertEq(listed[0], GUARDIAN1);
        assertEq(listed[1], GUARDIAN2);
        assertEq(listed[2], GUARDIAN3);
    }

    function test_DuplicateGuardianRejected() public {
        registry.addGuardian(WALLET, GUARDIAN1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IGuardianRegistry.GuardianAlreadyActive.selector, WALLET, GUARDIAN1
            )
        );
        registry.addGuardian(WALLET, GUARDIAN1);
        assertEq(registry.guardianCount(WALLET), 1);
    }

    function test_RemoveGuardian() public {
        registry.addGuardian(WALLET, GUARDIAN1);
        registry.addGuardian(WALLET, GUARDIAN2);
        registry.addGuardian(WALLET, GUARDIAN3);

        registry.removeGuardian(WALLET, GUARDIAN1);

        assertFalse(registry.isGuardian(WALLET, GUARDIAN1));
        assertTrue(registry.isGuardian(WALLET, GUARDIAN2));
        assertTrue(registry.isGuardian(WALLET, GUARDIAN3));
        assertEq(registry.guardianCount(WALLET), 2);

        address[] memory listed = registry.getGuardians(WALLET);
        assertEq(listed.length, 2);
        // Swap-and-pop: remaining members stay members regardless of order.
        bool hasG2;
        bool hasG3;
        for (uint256 i = 0; i < listed.length; ++i) {
            hasG2 = hasG2 || listed[i] == GUARDIAN2;
            hasG3 = hasG3 || listed[i] == GUARDIAN3;
        }
        assertTrue(hasG2 && hasG3);
    }

    function test_UnknownGuardianRemovalRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(IGuardianRegistry.GuardianNotActive.selector, WALLET, GUARDIAN2)
        );
        registry.removeGuardian(WALLET, GUARDIAN2);
    }

    function test_ReRemovedGuardianCanBeAddedAgain() public {
        registry.addGuardian(WALLET, GUARDIAN1);
        registry.removeGuardian(WALLET, GUARDIAN1);
        registry.addGuardian(WALLET, GUARDIAN1);
        assertTrue(registry.isGuardian(WALLET, GUARDIAN1));
        assertEq(registry.guardianCount(WALLET), 1);
        assertEq(registry.getGuardians(WALLET).length, 1);
    }

    function test_ZeroAddressesRejected() public {
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        registry.addGuardian(address(0), GUARDIAN1);

        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        registry.addGuardian(WALLET, address(0));

        // Removing the zero address simply reports it as inactive.
        vm.expectRevert(
            abi.encodeWithSelector(IGuardianRegistry.GuardianNotActive.selector, WALLET, address(0))
        );
        registry.removeGuardian(WALLET, address(0));
    }

    function test_WalletsAreIsolated() public {
        registry.addGuardian(WALLET, GUARDIAN1);
        registry.addGuardian(WALLET_B, GUARDIAN2);

        assertFalse(registry.isGuardian(WALLET, GUARDIAN2));
        assertFalse(registry.isGuardian(WALLET_B, GUARDIAN1));
        assertEq(registry.guardianCount(WALLET), 1);
        assertEq(registry.guardianCount(WALLET_B), 1);

        registry.removeGuardian(WALLET, GUARDIAN1);
        assertTrue(registry.isGuardian(WALLET_B, GUARDIAN2), "wallet B must be untouched");
        assertEq(registry.guardianCount(WALLET_B), 1);
    }
}
