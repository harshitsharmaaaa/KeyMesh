// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {IGuardianRegistry} from "../src/interfaces/IGuardianRegistry.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {IRecoveryManager} from "../src/interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";

/// @notice Phase 1.2 guardian recovery: bootstrap, lifecycle state machine,
/// authority boundaries, timelock, isolation, and device-replacement effects.
contract RecoveryManagerTest is Test {
    GuardianRegistry internal registry;
    RecoveryManager internal recovery;
    KeymeshWallet internal wallet;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant STRANGER_KEY = 0xFEED;

    uint256 internal constant G1_KEY = 0x1001;
    uint256 internal constant G2_KEY = 0x1002;
    uint256 internal constant G3_KEY = 0x1003;
    uint256 internal constant G4_KEY = 0x1004;
    uint256 internal constant G5_KEY = 0x1005;

    address internal device;
    address internal device2;
    address internal stranger;
    address internal g1;
    address internal g2;
    address internal g3;
    address internal g4;
    address internal g5;

    uint64 internal constant TIMELOCK = 24 hours;
    uint256 internal constant EXPIRY = 2_100_000_000;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);
        g1 = vm.addr(G1_KEY);
        g2 = vm.addr(G2_KEY);
        g3 = vm.addr(G3_KEY);
        g4 = vm.addr(G4_KEY);
        g5 = vm.addr(G5_KEY);

        vm.warp(2_099_000_000);

        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));
        // This test contract acts as each wallet's bootstrap manager.
        wallet = _newWallet(device);
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    function _newWallet(address initialDevice) internal returns (KeymeshWallet) {
        return new KeymeshWallet(address(this), initialDevice, address(recovery), address(0));
    }

    function _bootstrapGuardians() internal returns (address[] memory guardians) {
        guardians = new address[](3);
        guardians[0] = g1;
        guardians[1] = g2;
        guardians[2] = g3;
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, TIMELOCK);
    }

    function _bootstrap(KeymeshWallet target, address[] memory guardians, uint256 quorum) internal {
        recovery.bootstrapRecoveryGovernance(address(target), guardians, quorum, TIMELOCK);
    }

    /// @notice Device-signed governance call routed through wallet.execute,
    /// exactly how production device management reaches the RecoveryManager.
    function _governViaDevice(uint256 deviceKey, bytes memory data) internal {
        (bytes memory sig, uint256 nonce) = _signGovern(deviceKey, data);
        wallet.execute({
            wallet: address(wallet),
            chainId: block.chainid,
            to: address(recovery),
            value: 0,
            data: data,
            nonce: nonce,
            expiry: EXPIRY,
            signature: sig
        });
    }

    /// @notice Same as {_governViaDevice} for calls expected to revert. The
    /// signature is produced BEFORE arming expectRevert because Foundry treats
    /// any intermediate call (including getNonce view calls) as the "next
    /// call" and consumes the expectation.
    function _governExpectRevert(uint256 deviceKey, bytes memory data, bytes memory innerErr)
        internal
    {
        (bytes memory sig, uint256 nonce) = _signGovern(deviceKey, data);
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.ExecutionFailed.selector, innerErr));
        wallet.execute({
            wallet: address(wallet),
            chainId: block.chainid,
            to: address(recovery),
            value: 0,
            data: data,
            nonce: nonce,
            expiry: EXPIRY,
            signature: sig
        });
    }

    function _signGovern(uint256 deviceKey, bytes memory data)
        internal
        view
        returns (bytes memory sig, uint256 nonce)
    {
        nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(recovery), 0, data, EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
        return (abi.encodePacked(r, s, v), nonce);
    }

    function _addGuardianData(address guardian) internal view returns (bytes memory) {
        return abi.encodeCall(IRecoveryManager.addGuardian, (address(wallet), guardian));
    }

    function _removeGuardianData(address guardian) internal view returns (bytes memory) {
        return abi.encodeCall(IRecoveryManager.removeGuardian, (address(wallet), guardian));
    }

    function _setQuorumData(uint256 quorum) internal view returns (bytes memory) {
        return abi.encodeCall(IRecoveryManager.setQuorum, (address(wallet), quorum));
    }

    function _setTimelockData(uint64 seconds_) internal view returns (bytes memory) {
        return abi.encodeCall(IRecoveryManager.setRecoveryTimelock, (address(wallet), seconds_));
    }

    function _initiate(address replaced, address newDev) internal returns (uint256) {
        vm.prank(device); // an authorized device initiates
        recovery.initiateRecovery(address(wallet), replaced, newDev);
        return recovery.latestRecoveryIdOf(address(wallet));
    }

    /// @notice Governance calls travel through wallet.execute, so inner custom
    /// errors surface wrapped as `ExecutionFailed(returnData)`.
    function _expectGovernRevert(bytes memory data, bytes memory innerRevertData) internal {
        _governExpectRevert(DEVICE_KEY, data, innerRevertData);
    }

    function _approve(address guardian) internal {
        vm.prank(guardian);
        recovery.approveRecovery(address(wallet));
    }

    function _reachQuorum() internal returns (uint256 id) {
        id = _initiate(device, device2);
        uint64 expectedEnd = uint64(block.timestamp) + TIMELOCK;
        _approve(g1);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Pending)
        );
        vm.expectEmit(true, true, true, true);
        emit IRecoveryManager.RecoveryTimelockStarted(id, address(wallet), expectedEnd);
        _approve(g2);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.QuorumReached)
        );
        return id;
    }

    // ---------------------------------------------------------------
    // bootstrap
    // ---------------------------------------------------------------

    function test_BootstrapSetsGuardiansQuorumTimelock() public {
        vm.expectEmit(true, false, false, true);
        emit IRecoveryManager.GuardianSetAdded(address(wallet), _threeGuardians(), 2);
        _bootstrapGuardians();

        assertTrue(wallet.recoveryInitialized());
        assertTrue(registry.isGuardian(address(wallet), g1));
        assertTrue(registry.isGuardian(address(wallet), g2));
        assertTrue(registry.isGuardian(address(wallet), g3));
        assertFalse(registry.isGuardian(address(wallet), g4));
        assertEq(registry.guardianCount(address(wallet)), 3);
        assertEq(recovery.quorumOf(address(wallet)), 2);
        assertEq(recovery.recoveryTimelockSeconds(address(wallet)), TIMELOCK);
    }

    function test_NonManagerCannotBootstrap() public {
        address[] memory guardians = _threeGuardians();
        vm.prank(stranger);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, TIMELOCK);
    }

    function test_ManagerOfOtherWalletCannotBootstrap() public {
        // The manager of `wallet` cannot bootstrap a wallet managed by someone
        // else — bootstrap authority is strictly per-wallet.
        KeymeshWallet foreign = new KeymeshWallet(stranger, stranger, address(recovery), address(0));
        address[] memory guardians = _threeGuardians();
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.bootstrapRecoveryGovernance(address(foreign), guardians, 1, TIMELOCK);
        assertFalse(foreign.recoveryInitialized(), "foreign wallet untouched");
    }

    function test_DoubleBootstrapRejected() public {
        _bootstrapGuardians();
        address[] memory guardians = _threeGuardians();
        vm.expectRevert(KeymeshErrors.AlreadyInitialized.selector);
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, TIMELOCK);
    }

    function test_BootstrapValidation() public {
        address[] memory empty = new address[](0);
        vm.expectRevert(KeymeshErrors.InvalidGuardianSet.selector);
        recovery.bootstrapRecoveryGovernance(address(wallet), empty, 1, TIMELOCK);

        address[] memory dup = new address[](2);
        dup[0] = g1;
        dup[1] = g1;
        vm.expectRevert(KeymeshErrors.InvalidGuardianSet.selector);
        recovery.bootstrapRecoveryGovernance(address(wallet), dup, 1, TIMELOCK);

        address[] memory zeroed = new address[](1);
        zeroed[0] = address(0);
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        recovery.bootstrapRecoveryGovernance(address(wallet), zeroed, 1, TIMELOCK);

        address[] memory solo = new address[](1);
        solo[0] = g1;

        vm.expectRevert(
            abi.encodeWithSelector(KeymeshErrors.InvalidQuorum.selector, uint256(0), uint256(1))
        );
        recovery.bootstrapRecoveryGovernance(address(wallet), solo, 0, TIMELOCK);

        vm.expectRevert(
            abi.encodeWithSelector(KeymeshErrors.InvalidQuorum.selector, uint256(2), uint256(1))
        );
        recovery.bootstrapRecoveryGovernance(address(wallet), solo, 2, TIMELOCK);

        // Hoist view reads: any call after expectRevert (even a staticcall)
        // consumes the expectation.
        uint64 tooShort = recovery.MIN_TIMELOCK() - 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                KeymeshErrors.TimelockTooShort.selector, tooShort, recovery.MIN_TIMELOCK()
            )
        );
        recovery.bootstrapRecoveryGovernance(address(wallet), solo, 1, tooShort);
    }

    function test_BootstrapMinimumTimelockBoundaryAccepted() public {
        address[] memory solo = new address[](1);
        solo[0] = g1;
        uint64 minimum = recovery.MIN_TIMELOCK();
        recovery.bootstrapRecoveryGovernance(address(wallet), solo, 1, minimum);
        assertEq(recovery.recoveryTimelockSeconds(address(wallet)), minimum);
    }

    // ---------------------------------------------------------------
    // transitional manager authority ends at initialization
    // ---------------------------------------------------------------

    function test_ManagerCanRegisterDevicesOnlyBeforeInitialization() public {
        wallet.registerDevice(device2);
        assertTrue(wallet.isDeviceAuthorized(device2));

        _bootstrapGuardians();

        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.ManagerAuthorityRetired.selector, address(this))
        );
        wallet.registerDevice(stranger);
        assertFalse(wallet.isDeviceAuthorized(stranger));
    }

    function test_ManagerCannotRevokeAfterInitialization() public {
        wallet.registerDevice(device2);
        _bootstrapGuardians();

        vm.prank(device2);
        wallet.revokeDevice(device2); // self-revocation remains available
        assertFalse(wallet.isDeviceAuthorized(device2));

        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.NotDeviceManager.selector, address(this))
        );
        wallet.revokeDevice(device); // manager path is dead post-init
        assertTrue(wallet.isDeviceAuthorized(device));
    }

    function test_ManagerCannotTouchRecoveryAfterInitialization() public {
        _bootstrapGuardians();

        // Not a guardian or device -> cannot initiate...
        vm.prank(address(this)); // the retired manager
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, address(this))
        );
        recovery.initiateRecovery(address(wallet), device, device2);

        // ...cannot approve an open request (not a guardian of this wallet)...
        uint256 id = _initiate(device, device2);
        vm.prank(address(this));
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, address(this))
        );
        recovery.approveRecovery(address(wallet));

        // ...and cannot cancel.
        vm.prank(address(this));
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.cancelRecovery(address(wallet));

        // Only devices can stop it.
        vm.prank(device);
        recovery.cancelRecovery(address(wallet));
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Cancelled)
        );
    }

    // ---------------------------------------------------------------
    // guardian-set governance (device-signed through wallet.execute)
    // ---------------------------------------------------------------

    function test_DeviceAddsAndRemovesGuardiansPostInitialization() public {
        _bootstrapGuardians();

        _governViaDevice(DEVICE_KEY, _addGuardianData(g4));
        assertTrue(registry.isGuardian(address(wallet), g4));
        assertEq(registry.guardianCount(address(wallet)), 4);

        _governViaDevice(DEVICE_KEY, _removeGuardianData(g4));
        assertFalse(registry.isGuardian(address(wallet), g4));
        assertEq(registry.guardianCount(address(wallet)), 3);
    }

    function test_DuplicateAndZeroGuardianRejected() public {
        _bootstrapGuardians();

        _expectGovernRevert(
            _addGuardianData(g1),
            abi.encodeWithSelector(
                IGuardianRegistry.GuardianAlreadyActive.selector, address(wallet), g1
            )
        );

        bytes memory zeroAdd =
            abi.encodeCall(IRecoveryManager.addGuardian, (address(wallet), address(0)));
        _expectGovernRevert(zeroAdd, abi.encodeWithSelector(KeymeshErrors.ZeroAddress.selector));
    }

    function test_GuardianManagementRequiresInitialization() public {
        _expectGovernRevert(
            _addGuardianData(g4), abi.encodeWithSelector(KeymeshErrors.NotInitialized.selector)
        );
    }

    function test_SetQuorumAndTimelockAffectFutureRecoveriesOnly() public {
        _bootstrapGuardians();

        _governViaDevice(DEVICE_KEY, _setQuorumData(3));
        assertEq(recovery.quorumOf(address(wallet)), 3);

        uint64 shorter = 2 days;
        _governViaDevice(DEVICE_KEY, _setTimelockData(shorter));
        assertEq(recovery.recoveryTimelockSeconds(address(wallet)), shorter);

        // Snapshot semantics: an in-flight recovery keeps the values from
        // initiation even after configuration changes.
        uint256 id = _initiate(device, device2);
        assertEq(recovery.quorumOf(address(wallet)), 3, "config changed");

        _governViaDevice(DEVICE_KEY, _setQuorumData(1));
        _approve(g1);
        _approve(g2);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Pending),
            "snapshot quorum of 3 still not reached with 2 approvals"
        );

        // Third approval satisfies the snapshot taken at initiation.
        _approve(g3);
        (,,,,,,, uint256 snapshotQuorum,) = recovery.requestById(id);
        assertEq(snapshotQuorum, 3);
    }

    function test_SetQuorumValidation() public {
        _bootstrapGuardians();

        _expectGovernRevert(
            _setQuorumData(0),
            abi.encodeWithSelector(KeymeshErrors.InvalidQuorum.selector, uint256(0), uint256(3))
        );

        _expectGovernRevert(
            _setQuorumData(4),
            abi.encodeWithSelector(KeymeshErrors.InvalidQuorum.selector, uint256(4), uint256(3))
        );

        bytes memory shortTimelock = _setTimelockData(uint64(recovery.MIN_TIMELOCK()) - 1);
        _expectGovernRevert(
            shortTimelock,
            abi.encodeWithSelector(
                KeymeshErrors.TimelockTooShort.selector,
                uint64(recovery.MIN_TIMELOCK() - 1),
                recovery.MIN_TIMELOCK()
            )
        );

        assertEq(recovery.quorumOf(address(wallet)), 2, "config unchanged by failed calls");
        assertEq(recovery.recoveryTimelockSeconds(address(wallet)), TIMELOCK);
    }

    function test_NonWalletCannotCallGovernanceFunctions() public {
        _bootstrapGuardians();

        vm.prank(device);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.addGuardian(address(wallet), g4); // direct call, bypassing wallet.execute

        vm.prank(device);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.setQuorum(address(wallet), 3);

        vm.startPrank(device);
        recovery.initiateRecovery(address(wallet), device, device2); // devices CAN initiate directly
        vm.stopPrank();
    }

    // ---------------------------------------------------------------
    // initiation
    // ---------------------------------------------------------------

    function test_GuardianCanInitiate() public {
        _bootstrapGuardians();
        vm.prank(g1);
        recovery.initiateRecovery(address(wallet), device, device2);

        uint256 id = recovery.latestRecoveryIdOf(address(wallet));
        (address reqWallet, address initiator,,,,,,,) = recovery.requestById(id);
        assertEq(reqWallet, address(wallet));
        assertEq(initiator, g1);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Pending)
        );
    }

    function test_DeviceCanInitiate() public {
        _bootstrapGuardians();
        uint256 id = _initiate(device, device2);
        assertTrue(id != 0);
    }

    function test_UnauthorizedInitiatorRejected() public {
        _bootstrapGuardians();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, stranger)
        );
        recovery.initiateRecovery(address(wallet), device, device2);

        vm.prank(address(this)); // retired manager
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, address(this))
        );
        recovery.initiateRecovery(address(wallet), device, device2);
    }

    function test_InitiationValidation() public {
        _bootstrapGuardians();

        vm.startPrank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.InvalidReplacementDevice.selector, address(0))
        );
        recovery.initiateRecovery(address(wallet), device, address(0));

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.InvalidReplacementDevice.selector, device2)
        );
        recovery.initiateRecovery(address(wallet), device2, device2);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.InvalidReplacementDevice.selector, device)
        );
        recovery.initiateRecovery(address(wallet), address(0), device); // already authorized

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.InvalidReplacedDevice.selector, stranger)
        );
        recovery.initiateRecovery(address(wallet), stranger, device2);
        vm.stopPrank();

        assertEq(
            recovery.latestRecoveryIdOf(address(wallet)), 0, "failed attempts leave no request"
        );
    }

    function test_SecondActiveRequestRejected() public {
        _bootstrapGuardians();
        _initiate(device, device2);

        vm.prank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.RecoveryAlreadyActive.selector, uint256(1))
        );
        recovery.initiateRecovery(address(wallet), device, g5);
    }

    function test_InitiationDoesNotChangeDeviceSet() public {
        _bootstrapGuardians();
        uint256 id = _initiate(device, device2);

        assertTrue(wallet.isDeviceAuthorized(device), "old device untouched");
        assertFalse(wallet.isDeviceAuthorized(device2), "new device NOT yet authorized");
        assertEq(wallet.deviceCount(), 1);
        (,,,,,,,, IRecoveryManager.RecoveryStatus st) = recovery.requestById(id);
        assertEq(uint8(st), uint8(IRecoveryManager.RecoveryStatus.Pending));
    }

    function test_UnsatisfiableQuorumBlocksInitiation() public {
        _bootstrapGuardians();
        // Devices remove guardians below the configured quorum of 2.
        _governViaDevice(DEVICE_KEY, _removeGuardianData(g1));
        _governViaDevice(DEVICE_KEY, _removeGuardianData(g2));
        assertEq(registry.guardianCount(address(wallet)), 1);

        vm.prank(device);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.UnsatisfiableQuorum.selector, uint256(2), uint256(1)
            )
        );
        recovery.initiateRecovery(address(wallet), device, device2);

        // Owner can restore consistency by lowering the quorum.
        _governViaDevice(DEVICE_KEY, _setQuorumData(1));
        vm.prank(device);
        recovery.initiateRecovery(address(wallet), device, device2);
        assertTrue(recovery.latestRecoveryIdOf(address(wallet)) != 0);
    }

    function test_InitiationRequiresInitializedGovernance() public {
        vm.prank(device);
        vm.expectRevert(KeymeshErrors.NotInitialized.selector);
        recovery.initiateRecovery(address(wallet), device, device2);
    }

    // ---------------------------------------------------------------
    // approvals
    // ---------------------------------------------------------------

    function test_ApproveOncePerGuardian() public {
        _bootstrapGuardians();
        uint256 id = _initiate(device, device2);

        _approve(g1);
        assertTrue(recovery.hasApproved(id, g1));

        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.DuplicateApproval.selector, g1));
        recovery.approveRecovery(address(wallet));
    }

    function test_NonGuardianCannotApprove() public {
        _bootstrapGuardians();
        _initiate(device, device2);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, stranger)
        );
        recovery.approveRecovery(address(wallet));

        vm.prank(device); // devices are not guardians
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, device)
        );
        recovery.approveRecovery(address(wallet));
    }

    function test_RemovedGuardianCannotApprove() public {
        _bootstrapGuardians();
        _governViaDevice(DEVICE_KEY, _removeGuardianData(g1));

        _initiate(device, device2);
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, g1));
        recovery.approveRecovery(address(wallet));
    }

    function test_ApprovalOnlyWhilePending() public {
        _bootstrapGuardians();
        _reachQuorum(); // leaves status QuorumReached

        vm.prank(g3);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.QuorumReached),
                "approve"
            )
        );
        recovery.approveRecovery(address(wallet));
    }

    function test_NoApprovalWithoutRequest() public {
        _bootstrapGuardians();
        vm.prank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.None),
                "approve"
            )
        );
        recovery.approveRecovery(address(wallet));
    }

    // ---------------------------------------------------------------
    // quorum configurations
    // ---------------------------------------------------------------

    function test_OneOfOne() public {
        address[] memory solo = new address[](1);
        solo[0] = g1;
        _bootstrap(wallet, solo, 1);

        _initiate(device, device2);
        _approve(g1);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.QuorumReached)
        );
    }

    function test_TwoOfThree() public {
        _bootstrapGuardians();

        _initiate(device, device2);
        _approve(g1);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Pending),
            "1 of 3 is not quorum"
        );
        _approve(g2);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.QuorumReached)
        );
    }

    function test_ThreeOfFive() public {
        address[] memory five = new address[](5);
        five[0] = g1;
        five[1] = g2;
        five[2] = g3;
        five[3] = g4;
        five[4] = g5;
        _bootstrap(wallet, five, 3);

        _initiate(device, device2);
        _approve(g5);
        _approve(g4);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Pending),
            "2 of 5 is not quorum"
        );
        _approve(g1);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.QuorumReached)
        );
    }

    function test_InsufficientApprovalsCannotFinalize() public {
        _bootstrapGuardians();
        _initiate(device, device2);
        _approve(g1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.Pending),
                "finalize"
            )
        );
        recovery.finalizeRecovery(address(wallet));
        assertFalse(wallet.isDeviceAuthorized(device2), "device set unchanged");
        assertTrue(wallet.isDeviceAuthorized(device), "old device intact");
    }

    // ---------------------------------------------------------------
    // timelock
    // ---------------------------------------------------------------

    function test_CannotFinalizeBeforeTimelockElapses() public {
        _bootstrapGuardians();
        uint256 id = _reachQuorum();
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(id);

        vm.warp(executeAfter - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.TimelockNotElapsed.selector, executeAfter, uint64(executeAfter - 1)
            )
        );
        recovery.finalizeRecovery(address(wallet));

        assertFalse(wallet.isDeviceAuthorized(device2));
    }

    function test_TimelockBoundaryIsInclusive() public {
        _bootstrapGuardians();
        _reachQuorum();
        (,,,,, uint64 executeAfter,,,) =
            recovery.requestById(recovery.latestRecoveryIdOf(address(wallet)));

        vm.warp(executeAfter); // exactly at the deadline: executable now
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Executable)
        );
        recovery.finalizeRecovery(address(wallet));
        assertTrue(wallet.isDeviceAuthorized(device2));
    }

    function test_FinalizeAfterTimelockByAnyone() public {
        _bootstrapGuardians();
        _reachQuorum();

        vm.warp(block.timestamp + TIMELOCK + 7 days);
        vm.prank(stranger); // finalization is permissionless
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2));
        assertFalse(wallet.isDeviceAuthorized(device));
    }

    function test_LazyPromotionToExecutableIsAuditable() public {
        _bootstrapGuardians();
        _initiate(device, device2);
        _approve(g1);
        _approve(g2);

        // Still QuorumReached while the timelock runs...
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.QuorumReached)
        );
        vm.warp(block.timestamp + TIMELOCK);
        // ...and becomes Executable once elapsed (inclusive boundary).
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Executable)
        );
    }

    // ---------------------------------------------------------------
    // cancellation
    // ---------------------------------------------------------------

    function test_DeviceCancelsPendingRecovery() public {
        _bootstrapGuardians();
        uint256 id = _initiate(device, device2);

        vm.prank(device);
        vm.expectEmit(true, true, true, true);
        emit IRecoveryManager.RecoveryCancelled(id, address(wallet), device);
        recovery.cancelRecovery(address(wallet));

        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Cancelled)
        );
        assertEq(
            recovery.latestRecoveryIdOf(address(wallet)),
            id,
            "terminal request stays queryable under its id"
        );
    }

    function test_DeviceCancelsExecutableRecovery() public {
        _bootstrapGuardians();
        _reachQuorum();
        vm.warp(block.timestamp + TIMELOCK);
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Executable)
        );

        vm.prank(device);
        recovery.cancelRecovery(address(wallet)); // any active device may stop it
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Cancelled)
        );

        vm.expectRevert();
        recovery.finalizeRecovery(address(wallet));
        assertFalse(wallet.isDeviceAuthorized(device2));
        assertTrue(wallet.isDeviceAuthorized(device), "old device intact after cancellation");
    }

    function test_CancelledRecoveryCannotBeApprovedOrRevived() public {
        _bootstrapGuardians();
        uint256 id = _initiate(device, device2);
        _approve(g1);

        vm.prank(device);
        recovery.cancelRecovery(address(wallet));

        vm.prank(g2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.Cancelled),
                "approve"
            )
        );
        recovery.approveRecovery(address(wallet));

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.Cancelled),
                "finalize"
            )
        );
        recovery.finalizeRecovery(address(wallet));

        // Cancelling twice is impossible: the request is terminal.
        vm.prank(device);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.Cancelled),
                "cancel"
            )
        );
        recovery.cancelRecovery(address(wallet));

        // A fresh request collects approvals from scratch under a new id.
        uint256 newId = _initiate(device, device2);
        assertTrue(newId > id, "recovery ids never reused");
        assertFalse(recovery.hasApproved(newId, g1), "no partial credit across attempts");
    }

    function test_OnlyDevicesMayCancel() public {
        _bootstrapGuardians();
        _initiate(device, device2);

        vm.prank(g1); // guardians cannot cancel (by design)
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.cancelRecovery(address(wallet));

        vm.prank(stranger);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.cancelRecovery(address(wallet));
    }

    // ---------------------------------------------------------------
    // finalization effects
    // ---------------------------------------------------------------

    function test_FinalizeAuthorizesNewAndRevokesOld() public {
        wallet.registerDevice(g4); // multi-device wallet: recover ONE slot
        _bootstrapGuardians();
        uint256 id = _initiate(g4, device2);
        _approve(g1);
        _approve(g2);
        vm.warp(block.timestamp + TIMELOCK);

        vm.expectEmit(true, true, true, true);
        emit IRecoveryManager.RecoveryFinalized(id, address(wallet), device2, g4);
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2), "new device authorized");
        assertFalse(wallet.isDeviceAuthorized(g4), "replaced device revoked");
        assertTrue(wallet.isDeviceAuthorized(device), "unrelated device kept");
        assertEq(wallet.deviceCount(), 2);

        (,,,,,,,, IRecoveryManager.RecoveryStatus st) = recovery.requestById(id);
        assertEq(uint8(st), uint8(IRecoveryManager.RecoveryStatus.Executed));
        assertEq(
            recovery.latestRecoveryIdOf(address(wallet)), id, "executed record stays queryable"
        );
    }

    function test_TotalDeviceLossRecoveryAddsWithoutRevoking() public {
        _bootstrapGuardians();
        // replacedDevice = 0 models "all devices lost": pure addition.
        _initiate(address(0), device2);
        _approve(g1);
        _approve(g2);
        vm.warp(block.timestamp + TIMELOCK);
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2));
        assertTrue(wallet.isDeviceAuthorized(device), "nothing was revoked");
        assertEq(wallet.deviceCount(), 2);
    }

    function test_ReplacedDeviceRevokedMidFlightRevertsAtomically() public {
        wallet.registerDevice(g4); // spare device keeps self-revocation legal
        _bootstrapGuardians();
        _reachQuorum();
        vm.warp(block.timestamp + TIMELOCK);

        // The replaced device disappears between initiation and finalization.
        vm.prank(device);
        wallet.revokeDevice(device); // self-revocation is always available
        assertTrue(recovery.statusOf(address(wallet)) == IRecoveryManager.RecoveryStatus.Executable);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.NotRegistered.selector, device));
        recovery.finalizeRecovery(address(wallet));

        // Atomicity: nothing changed anywhere.
        assertEq(
            uint8(recovery.statusOf(address(wallet))),
            uint8(IRecoveryManager.RecoveryStatus.Executable),
            "recovery state unchanged on failed finalization"
        );
        assertFalse(wallet.isDeviceAuthorized(device));
        assertFalse(wallet.isDeviceAuthorized(device2), "new device state unchanged");
        assertTrue(wallet.isDeviceAuthorized(g4));
        assertEq(wallet.deviceCount(), 1);
        assertEq(recovery.latestRecoveryIdOf(address(wallet)), 1, "still active for retry/cancel");
    }

    function test_DoubleFinalizationRejected() public {
        _bootstrapGuardians();
        _reachQuorum();
        vm.warp(block.timestamp + TIMELOCK);

        recovery.finalizeRecovery(address(wallet));
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.InvalidStateTransition.selector,
                uint8(IRecoveryManager.RecoveryStatus.Executed),
                "finalize"
            )
        );
        recovery.finalizeRecovery(address(wallet));

        assertEq(wallet.deviceCount(), 1, "no duplicate authorization");
    }

    function test_NewDeviceSignsAndOldDeviceCannotAfterRecovery() public {
        _bootstrapGuardians();
        _reachQuorum();
        vm.warp(block.timestamp + TIMELOCK);
        recovery.finalizeRecovery(address(wallet));

        // Capture the nonce BEFORE arming expectRevert: Foundry treats any
        // intermediate call (even a view) as "the next call".
        uint256 nonce = wallet.getNonce();

        // Old device: rejected at the wallet.
        bytes32 oldDigest =
            KeymeshTx.digest(address(wallet), block.chainid, nonce, device, 0, "", EXPIRY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_KEY, oldDigest);
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.UnauthorizedDevice.selector, device));
        wallet.execute({
            wallet: address(wallet),
            chainId: block.chainid,
            to: device,
            value: 0,
            data: "",
            nonce: nonce,
            expiry: EXPIRY,
            signature: abi.encodePacked(r, s, v)
        });

        // New device: full signing authority.
        bytes32 newDigest =
            KeymeshTx.digest(address(wallet), block.chainid, wallet.getNonce(), g1, 0, "", EXPIRY);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(DEVICE2_KEY, newDigest);
        wallet.execute({
            wallet: address(wallet),
            chainId: block.chainid,
            to: g1,
            value: 0,
            data: "",
            nonce: wallet.getNonce(),
            expiry: EXPIRY,
            signature: abi.encodePacked(r2, s2, v2)
        });
        assertEq(wallet.getNonce(), 1);
    }

    // ---------------------------------------------------------------
    // cross-wallet isolation
    // ---------------------------------------------------------------

    function test_WalletAGuardianCannotControlWalletB() public {
        _bootstrapGuardians();

        // Second wallet with a disjoint guardian set and its own device.
        KeymeshWallet walletB = _newWallet(stranger);
        address[] memory bGuardians = new address[](1);
        bGuardians[0] = g4;
        _bootstrap(walletB, bGuardians, 1);

        vm.prank(stranger);
        recovery.initiateRecovery(address(walletB), stranger, g5);
        uint256 idB = recovery.latestRecoveryIdOf(address(walletB));

        // g1 guards wallet A only: cannot approve wallet B's recovery.
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, g1));
        recovery.approveRecovery(address(walletB));

        // g1 cannot initiate a recovery for wallet B either.
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, g1));
        recovery.initiateRecovery(address(walletB), stranger, g5);

        // Wallet A's device cannot cancel wallet B's recovery.
        vm.prank(device);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.cancelRecovery(address(walletB));

        // Completing wallet A's recovery must not touch wallet B's state.
        _initiate(device, device2);
        _approve(g1);
        _approve(g2);
        vm.warp(block.timestamp + TIMELOCK);
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2));
        assertFalse(walletB.isDeviceAuthorized(g5), "wallet B untouched");
        assertFalse(registry.isGuardian(address(walletB), g1), "wallet B guardians untouched");
        assertEq(recovery.latestRecoveryIdOf(address(walletB)), idB, "wallet B recovery untouched");
        assertFalse(recovery.hasApproved(idB, g1));
    }

    function test_GuardianCannotApproveOwnForeignWalletTwiceViaCrossCalls() public {
        // g1 guardians two wallets; approvals are tracked per recovery id, so
        // approving wallet A's recovery leaves wallet B's independent.
        _bootstrapGuardians();
        KeymeshWallet walletB = _newWallet(stranger);
        address[] memory bGuardians = new address[](2);
        bGuardians[0] = g1;
        bGuardians[1] = g2;
        _bootstrap(walletB, bGuardians, 2);

        uint256 idA = _initiate(device, device2);
        _approve(g1);
        assertTrue(recovery.hasApproved(idA, g1));

        vm.prank(stranger);
        recovery.initiateRecovery(address(walletB), stranger, g5);
        uint256 idB = recovery.latestRecoveryIdOf(address(walletB));
        assertTrue(idB != idA);
        assertFalse(recovery.hasApproved(idB, g1), "approval did not leak across wallets");
        vm.prank(g1);
        recovery.approveRecovery(address(walletB)); // independent approval on B
        assertTrue(recovery.hasApproved(idB, g1));
    }

    // ---------------------------------------------------------------
    // misc
    // ---------------------------------------------------------------

    function test_MinTimelockConstant() public view {
        assertEq(recovery.MIN_TIMELOCK(), 1 hours);
    }

    // ---------------------------------------------------------------
    // internal utils
    // ---------------------------------------------------------------

    function _threeGuardians() internal view returns (address[] memory a) {
        a = new address[](3);
        a[0] = g1;
        a[1] = g2;
        a[2] = g3;
    }
}

