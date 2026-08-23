// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {IRecoveryManager} from "../src/interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

contract RecoveryManagerTest is Test {
    GuardianRegistry internal registry;
    RecoveryManager internal recovery;

    address internal constant WALLET = address(0xA11CE);
    address internal constant NEW_DEVICE = address(0x0D0);
    uint64 internal constant TIMELOCK = 7 days;

    function setUp() public {
        registry = new GuardianRegistry();
        recovery = new RecoveryManager(registry);

        // Register three guardians (weight 1 each) as the wallet itself.
        vm.startPrank(WALLET);
        registry.addGuardian(WALLET, address(0x1), 1);
        registry.addGuardian(WALLET, address(0x2), 1);
        registry.addGuardian(WALLET, address(0x3), 1);
        vm.stopPrank();
    }

    function _initiate(uint256 requiredWeight) internal {
        recovery.initiateRecovery(WALLET, NEW_DEVICE, requiredWeight, TIMELOCK);
    }

    function test_InitiateStartsPendingState() public {
        _initiate(2);

        assertEq(
            uint8(recovery.stateOf(WALLET)),
            uint8(IRecoveryManager.RecoveryState.Pending)
        );
        assertEq(recovery.approvalsWeightOf(WALLET), 0);
    }

    function test_ReachingThresholdStartsTimelock() public {
        _initiate(2);

        vm.prank(address(0x1));
        recovery.approveRecovery(WALLET);
        assertEq(
            uint8(recovery.stateOf(WALLET)),
            uint8(IRecoveryManager.RecoveryState.Pending),
            "below threshold must stay pending"
        );

        vm.prank(address(0x2));
        recovery.approveRecovery(WALLET);
        assertEq(
            uint8(recovery.stateOf(WALLET)),
            uint8(IRecoveryManager.RecoveryState.TimelockActive)
        );
        assertEq(recovery.timelockEndsAt(WALLET), block.timestamp + TIMELOCK);
    }

    function test_CannotCompleteBeforeTimelockElapses() public {
        _initiate(1);
        vm.prank(address(0x1));
        recovery.approveRecovery(WALLET);

        vm.warp(block.timestamp + TIMELOCK - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.TimelockNotElapsed.selector,
                block.timestamp + 1,
                block.timestamp
            )
        );
        recovery.completeRecovery(WALLET);

        vm.warp(block.timestamp + 1); // exactly at the deadline
        recovery.completeRecovery(WALLET);
        assertEq(uint8(recovery.stateOf(WALLET)), uint8(IRecoveryManager.RecoveryState.Completed));
    }

    function test_NonGuardianCannotApprove() public {
        _initiate(1);
        vm.prank(address(0xDEAD));
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, address(0xDEAD))
        );
        recovery.approveRecovery(WALLET);
    }

    function test_DoubleApprovalRejected() public {
        _initiate(3);
        vm.prank(address(0x1));
        recovery.approveRecovery(WALLET);

        vm.prank(address(0x1));
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.DuplicateApproval.selector, address(0x1)));
        recovery.approveRecovery(WALLET);
    }

    function test_WeightedQuorumRespectsWeights() public {
        // weight-2 guardian alone satisfies a threshold of 2
        vm.prank(WALLET);
        registry.addGuardian(WALLET, address(0x4), 2);

        _initiate(2);
        vm.prank(address(0x4));
        recovery.approveRecovery(WALLET);
        assertEq(uint8(recovery.stateOf(WALLET)), uint8(IRecoveryManager.RecoveryState.TimelockActive));
    }

    function test_CancelStopsActiveRecovery() public {
        _initiate(1);
        recovery.cancelRecovery(WALLET);
        assertEq(uint8(recovery.stateOf(WALLET)), uint8(IRecoveryManager.RecoveryState.Cancelled));

        vm.prank(address(0x1));
        vm.expectRevert(IRecoveryManager.NoActiveRecovery.selector);
        recovery.approveRecovery(WALLET);
    }

    function test_SecondInitiateBlockedWhileActive() public {
        _initiate(3);
        vm.expectRevert(IRecoveryManager.RecoveryAlreadyActive.selector);
        _initiate(3);
    }

    function test_ShortTimelockRejected() public {
        vm.expectRevert(IRecoveryManager.TimelockTooShort.selector);
        recovery.initiateRecovery(WALLET, NEW_DEVICE, 1, 7 days - 1);
    }

    function test_ZeroAddressesRejected() public {
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        recovery.initiateRecovery(address(0), NEW_DEVICE, 1, TIMELOCK);

        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        recovery.initiateRecovery(WALLET, address(0), 1, TIMELOCK);
    }
}
