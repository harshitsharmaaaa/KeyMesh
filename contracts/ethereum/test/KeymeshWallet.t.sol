// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

contract KeymeshWalletTest is Test {
    KeymeshWallet internal wallet;
    address internal constant DEVICE = address(0xD3);

    function setUp() public {
        wallet = new KeymeshWallet(address(this));
    }

    function test_AuthorizeAndRevokeDevice() public {
        wallet.authorizeDevice(DEVICE);
        assertTrue(wallet.isDeviceAuthorized(DEVICE));
        assertEq(wallet.deviceCount(), 1);

        vm.expectEmit(true, false, false, false);
        emit IKeymeshWallet.DeviceRevoked(DEVICE, 0);
        wallet.revokeDevice(DEVICE);

        assertFalse(wallet.isDeviceAuthorized(DEVICE));
        assertEq(wallet.deviceCount(), 0);
    }

    function test_NonOwnerCannotManageDevices() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        wallet.authorizeDevice(DEVICE);
    }

    function test_DoubleAuthorizeRejected() public {
        wallet.authorizeDevice(DEVICE);
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.AlreadyAuthorized.selector, DEVICE));
        wallet.authorizeDevice(DEVICE);
    }

    function test_ExecuteIsDisabledInPrototype() public {
        // The skeleton must never be able to move funds.
        vm.expectRevert(IKeymeshWallet.ExecutionNotYetImplemented.selector);
        wallet.execute(address(1), 1 ether, "");
    }

    function test_ZeroAddressOwnerRejected() public {
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        new KeymeshWallet(address(0));
    }
}

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
        vm.expectRevert(abi.encodeWithSelector(IPolicyManager.InvalidPolicy.selector, "normalWeight"));
        policyManager.setPolicy(WALLET, bad);

        IPolicyManager.Policy memory bad2 = _policy();
        bad2.recoveryWeight = 0;
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IPolicyManager.InvalidPolicy.selector, "recoveryWeight"));
        policyManager.setPolicy(WALLET, bad2);
    }
}
