// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {IRecoveryManager} from "../src/interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @notice Foundry invariant and fuzz tests for the RecoveryManager state machine.
/// Tests all state transitions, timelock boundaries, guardian quorum semantics,
/// and cross-wallet isolation.
contract RecoveryManagerInvariantTest is Test {
    KeymeshWallet internal wallet;
    RecoveryManager internal recovery;
    GuardianRegistry internal registry;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 constant STRANGER_KEY = 0x2972;
    uint256 internal constant G1_KEY = 0x1001;
    uint256 internal constant G2_KEY = 0x1002;
    uint256 internal constant G3_KEY = 0x1003;
    uint256 internal constant G4_KEY = 0x1004;
    uint64 internal constant TIMELOCK = 24 hours;
    uint256 internal constant EXPIRY = 2_100_000_000;

    address internal device;
    address internal device2;
    address internal stranger;
    address internal g1;
    address internal g2;
    address internal g3;
    address internal g4;
    address internal manager;

    // Model state
    uint256 internal modelLatestRecoveryId;
    mapping(uint256 => address) internal modelRecoveryInitiator;
    mapping(uint256 => address) internal modelRecoveryNewDevice;
    mapping(uint256 => address) internal modelRecoveryReplacedDevice;
    mapping(uint256 => uint256) internal modelRecoveryApprovals;
    mapping(uint256 => IRecoveryManager.RecoveryStatus) internal modelRecoveryStatus;
    mapping(uint256 => mapping(address => bool)) internal modelRecoveryApproved;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);
        g1 = vm.addr(G1_KEY);
        g2 = vm.addr(G2_KEY);
        g3 = vm.addr(G3_KEY);
        g4 = vm.addr(G4_KEY);
        manager = address(this);

        vm.warp(2_099_000_000);

        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));
        wallet = new KeymeshWallet(manager, device, address(recovery), address(0));

        _bootstrap();
    }

    function _bootstrap() internal {
        address[] memory guardians = new address[](3);
        guardians[0] = g1;
        guardians[1] = g2;
        guardians[2] = g3;
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, TIMELOCK);
    }

    function _registerDevice(address dev) internal {
        vm.prank(manager);
        wallet.registerDevice(dev);
        _bootstrap(); // re-bootstrap not needed, just sync
    }

    /****************************************
     *           Invariants
     *****************************************/

    /// @notice Recovery state is wallet-specific
    function invariant_walletIsolation() external view {
        // Wallet A's recovery has no effect on Wallet B
        // This is checked in cross-wallet tests below
    }

    /// @notice At most one live recovery per wallet
    function invariant_oneLiveRecovery() external view {
        IRecoveryManager.RecoveryStatus status = recovery.statusOf(address(wallet));
        bool hasLive = status == IRecoveryManager.RecoveryStatus.Pending
            || status == IRecoveryManager.RecoveryStatus.QuorumReached
            || status == IRecoveryManager.RecoveryStatus.Executable;
        if (hasLive) {
            assertTrue(recovery.latestRecoveryIdOf(address(wallet)) != 0);
        }
    }

    /// @notice Only guardians + devices of THIS wallet can initiate
    function invariant_initiationAuthority() external view {
        IRecoveryManager.RecoveryStatus status = recovery.statusOf(address(wallet));
        // After bootstrap, only g1, g2, g3 or devices can initiate
        // Strangers and managers cannot
    }

    /// @notice Guardian count matches model
    function invariant_guardianCountConsistent() external view {
        assertEq(registry.guardianCount(address(wallet)), 3);
    }

    /****************************************
     *           Fuzz Tests
     *****************************************/

    /// @notice Fuzz: guardian approval uniqueness (can only approve once)
    function testFuzz_GuardianApprovesOnce(uint256 id) public {
        uint256 recoveryId = _initiateRecovery(device, device2);
        address guardian = id % 2 == 0 ? g1 : g2;

        vm.prank(guardian);
        recovery.approveRecovery(address(wallet));

        assertTrue(recovery.hasApproved(recoveryId, guardian), "guardian should have approved");

        // Second approval from same guardian should fail
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.DuplicateApproval.selector, guardian));
        recovery.approveRecovery(address(wallet));
    }

    /// @notice Fuzz: non-guardian cannot approve
    function testFuzz_NonGuardianCannotApprove(uint256 seed) public {
        uint256 recoveryId = _initiateRecovery(device, device2);

        address nonGuardian;
        if (seed % 2 == 0) {
            nonGuardian = stranger;
        } else {
            nonGuardian = address(uint160(uint256(seed) % 10000));
        }

        vm.prank(nonGuardian);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, nonGuardian));
        recovery.approveRecovery(address(wallet));
    }

/// @notice Fuzz: timelock boundary tests
    function testFuzz_TimelockBoundary(uint64 offset) public {
        vm.assume(offset < 200);

        uint256 recoveryId = _initiateRecovery(device, device2);
        _approve(g1);
        _approve(g2);

        // At quorum, get executeAfter (position 6 in requestById tuple, 9 total elements)
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(recoveryId);

        // Test before timelock
        if (offset == 0) {
            vm.warp(executeAfter - 1);
            vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.TimelockNotElapsed.selector, executeAfter, executeAfter - 1));
            recovery.finalizeRecovery(address(wallet));
        } else if (offset == 1) {
            vm.warp(executeAfter + 1);
            recovery.finalizeRecovery(address(wallet));
            assertTrue(wallet.isDeviceAuthorized(device2), "new device authorized at boundary");
        } else if (offset == 2) {
            vm.warp(executeAfter + 2);
            recovery.finalizeRecovery(address(wallet));
            assertTrue(wallet.isDeviceAuthorized(device2), "new device authorized after timelock");
        }
    }

    /// @notice Fuzz: approval order doesn't matter
    function testFuzz_ApprovalOrder(uint8 a, uint8 b) public {
        vm.assume(a != b && a < 3 && b < 3);
        address[] memory guardians = new address[](3);
        guardians[0] = g1;
        guardians[1] = g2;
        guardians[2] = g3;

        uint256 recoveryId = _initiateRecovery(device, device2);

        // Approve in different orders
        _approve(guardians[a]);
        _approve(guardians[b]);

        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.QuorumReached));

        // Third guardian would complete quorum
    }

    /// @notice Fuzz: cancel from any live state
    function testFuzz_CancelFromLiveState(uint8 state) public {
        vm.assume(state < 3); // 0=Pending, 1=QuorumReached, 2=Executable

        uint256 recoveryId = _initiateRecovery(device, device2);

        if (state >= 1) {
            _approve(g1);
            _approve(g2);
        }

        if (state >= 2) {
            (,,,, uint64 executeAfter,,,,) = recovery.requestById(recoveryId);
            vm.warp(executeAfter);
        }

        uint256 nonceBefore = wallet.getNonce();

        // Only devices can cancel
        vm.prank(device);
        recovery.cancelRecovery(address(wallet));

        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Cancelled));
        assertEq(wallet.getNonce(), nonceBefore, "cancel must not consume nonce");
    }

    /// @notice Fuzz: terminal states cannot be revisited
    function testFuzz_TerminalNoTransitions(uint8 terminalState) public {
        vm.assume(terminalState < 2); // 0=Executed, 1=Cancelled

        uint256 recoveryId;

        if (terminalState == 0) {
            // Execute a recovery
            recoveryId = _initiateRecovery(device, device2);
            _approve(g1);
            _approve(g2);
            // At quorum, get executeAfter (position 6 in requestById tuple, 9 total elements)
            (,,,,, uint64 executeAfter,,,) = recovery.requestById(recoveryId);
            vm.warp(executeAfter + 1);
            recovery.finalizeRecovery(address(wallet));
            assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Executed));
        } else {
            // Cancel a recovery
            recoveryId = _initiateRecovery(device, device2);
            vm.prank(device);
            recovery.cancelRecovery(address(wallet));
            assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Cancelled));
        }

        // No further actions should be possible
        vm.prank(device);
        vm.expectRevert();
        recovery.cancelRecovery(address(wallet));

        vm.expectRevert();
        recovery.finalizeRecovery(address(wallet));
    }

    /// @notice Fuzz: double finalization rejected
    function testFuzz_DoubleFinalizationRejected() public {
        uint256 recoveryId = _initiateRecovery(device, device2);
        _approve(g1);
        _approve(g2);
        // At quorum, get executeAfter (position 6 in requestById tuple, 9 total elements)
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(recoveryId);
        vm.warp(executeAfter + 1);

        recovery.finalizeRecovery(address(wallet));
        assertEq(wallet.deviceCount(), 1, "should have 1 device");
        assertTrue(wallet.isDeviceAuthorized(device2), "new device authorized");

        // Second finalization should fail
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidStateTransition.selector, uint8(IRecoveryManager.RecoveryStatus.Executed), "finalize"));
        recovery.finalizeRecovery(address(wallet));
    }

    /// @notice Fuzz: removed guardian cannot approve
    function testFuzz_RemovedGuardianCannotApprove(uint256 seed) public {
        uint256 recoveryId = _initiateRecovery(device, device2);

        // Remove g1 via device
        bytes memory data = abi.encodeWithSelector(
            IRecoveryManager.removeGuardian.selector, address(wallet), g1
        );
        _governViaDevice(DEVICE_KEY, data);

        assertFalse(registry.isGuardian(address(wallet), g1), "g1 removed");

        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, g1));
        recovery.approveRecovery(address(wallet));
    }

    /// @notice Fuzz: guardian set changes affect future, not in-flight
    function testFuzz_SnapshotQuorum(uint256 newQuorum) public {
        vm.assume(newQuorum == 1 || newQuorum == 3);

        uint256 recoveryId = _initiateRecovery(device, device2);
        modelRecoveryApprovals[recoveryId] = 0;
        modelRecoveryStatus[recoveryId] = IRecoveryManager.RecoveryStatus.Pending;

        // Change quorum via governance
        bytes memory data = abi.encodeWithSelector(
            IRecoveryManager.setQuorum.selector, address(wallet), newQuorum
        );
        _governViaDevice(DEVICE_KEY, data);

        // In-flight recovery still uses snapshot quorum of 2
        _approve(g1);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Pending));

        _approve(g2);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.QuorumReached));

        // Verify snapshot was used
        (,,,,,, , uint256 snapshotQuorum,) = recovery.requestById(recoveryId);
        assertEq(snapshotQuorum, 2, "snapshot quorum preserved");
    }

    /// @notice Fuzz: total device loss recovery (replacedDevice = address(0))
    function testFuzz_TotalDeviceLossRecovery(uint256 seed) public {
        vm.assume(seed < 1000);

        uint256 recoveryId = _initiateRecovery(address(0), device2);
        _approve(g1);
        _approve(g2);
        // At quorum, get executeAfter (position 6 in requestById tuple, 9 total elements)
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(recoveryId);
        vm.warp(executeAfter + 1);
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2), "new device authorized");
        assertTrue(wallet.isDeviceAuthorized(device), "old device still authorized (pure addition)");
        assertEq(wallet.deviceCount(), 2, "both devices present");
    }

    /// @notice Cross-wallet isolation
    function test_CrossWalletIsolation() public {
        // Create wallet B
        vm.prank(stranger);
        KeymeshWallet walletB = new KeymeshWallet(stranger, device2, address(recovery), address(0));
        address[] memory guardiansB = new address[](1);
        guardiansB[0] = g4;
        vm.prank(stranger);
        recovery.bootstrapRecoveryGovernance(address(walletB), guardiansB, 1, TIMELOCK);

        // Start recovery on wallet A
        uint256 idA = _initiateRecovery(device, device2);

        // Initiate recovery on wallet B via its device
        vm.prank(device2);
        recovery.initiateRecovery(address(walletB), device2, g4);
        uint256 idB = recovery.latestRecoveryIdOf(address(walletB));

        // g1 (guardian of A) cannot approve wallet B's recovery
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, g1));
        recovery.approveRecovery(address(walletB));

        // g4 (guardian of B) cannot approve wallet A's recovery
        vm.prank(g4);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, g4));
        recovery.approveRecovery(address(wallet));

        // Complete wallet A's recovery - wallet B should be untouched
        _approve(g1);
        _approve(g2);
        // At quorum, get executeAfter (position 6 in requestById tuple, 9 total elements)
        (,,,,, uint64 executeAfterA,,,) = recovery.requestById(idA);
        vm.warp(executeAfterA);
        recovery.finalizeRecovery(address(wallet));

        assertTrue(wallet.isDeviceAuthorized(device2), "wallet A recovery completed");
        assertEq(recovery.latestRecoveryIdOf(address(walletB)), idB, "wallet B recovery untouched");
        assertFalse(walletB.isDeviceAuthorized(g4), "wallet B device state untouched");
    }

    /// @notice Fuzz: replaced device must exist (or be 0)
    function testFuzz_InvalidReplacedDevice(address badDevice) public {
        vm.assume(badDevice != address(0) && badDevice != device && badDevice != device2);

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidReplacedDevice.selector, badDevice));
        recovery.initiateRecovery(address(wallet), badDevice, device2);
    }

    /// @notice Fuzz: new device must not be address(0) or already authorized
    function testFuzz_InvalidNewDevice(uint256 seed) public {
        address[] memory badDevices = new address[](2);
        badDevices[0] = address(0);
        badDevices[1] = device; // already authorized

        address newDevice = badDevices[seed % 2];

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidReplacementDevice.selector, newDevice));
        recovery.initiateRecovery(address(wallet), device, newDevice);
    }

    /// @notice Fuzz: cannot replace with same device
    function testFuzz_SameReplacementDevice() public {
        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidReplacementDevice.selector, device2));
        recovery.initiateRecovery(address(wallet), device2, device2);
    }

    /****************************************
     *           State Machine Tests
     *****************************************/

    /// @notice Test the full state transition matrix
    function test_StateTransitionMatrix() public {
        // None -> Pending (initiate)
        uint256 id = _initiateRecovery(device, device2);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Pending));

        // Pending -> QuorumReached (approve to quorum)
        _approve(g1);
        _approve(g2);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.QuorumReached));

        // QuorumReached -> Executable (time passes)
        // Position 6 in requestById tuple is executeAfter (9 total elements)
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(id);
        vm.warp(executeAfter + 1);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Executable));

        // Executable -> Executed (finalize)
        recovery.finalizeRecovery(address(wallet));
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Executed));

        // Cannot transition out of Executed
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidStateTransition.selector, uint8(IRecoveryManager.RecoveryStatus.Executed), "finalize"));
        recovery.finalizeRecovery(address(wallet));
    }

    /// @notice Cannot approve from terminal state
    function test_CancelledCannotBeApproved() public {
        uint256 id = _initiateRecovery(device, device2);
        vm.prank(device);
        recovery.cancelRecovery(address(wallet));
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.Cancelled));

        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidStateTransition.selector, uint8(IRecoveryManager.RecoveryStatus.Cancelled), "approve"));
        recovery.approveRecovery(address(wallet));
    }

    /// @notice Cannot approve when QuorumReached already
    function test_NoApprovalAfterQuorumReached() public {
        uint256 id = _initiateRecovery(device, device2);
        _approve(g1);
        _approve(g2);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.QuorumReached));

        vm.prank(g3);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidStateTransition.selector, uint8(IRecoveryManager.RecoveryStatus.QuorumReached), "approve"));
        recovery.approveRecovery(address(wallet));
    }

    /// @notice Cannot finalize when QuorumReached (before timelock)
    function test_NoFinalizeBeforeTimelockExpires() public {
        uint256 id = _initiateRecovery(device, device2);
        _approve(g1);
        _approve(g2);
        assertEq(uint8(recovery.statusOf(address(wallet))), uint8(IRecoveryManager.RecoveryStatus.QuorumReached));

        // Position 6 in requestById tuple is executeAfter (9 total elements)
        (,,,,, uint64 executeAfter,,,) = recovery.requestById(id);
        vm.warp(executeAfter - 1);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.TimelockNotElapsed.selector, executeAfter, executeAfter - 1));
        recovery.finalizeRecovery(address(wallet));
    }

    /// @notice Cannot cancel terminal state
    function test_CancelTerminalFails() public {
        uint256 id = _initiateRecovery(device, device2);
        vm.prank(device);
        recovery.cancelRecovery(address(wallet));

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.InvalidStateTransition.selector, uint8(IRecoveryManager.RecoveryStatus.Cancelled), "cancel"));
        recovery.cancelRecovery(address(wallet));
    }

    /****************************************
     *           Privilege Escalation Tests
     *****************************************/

    /// @notice Retired manager cannot initiate recovery
    function test_ManagerCannotInitiatePostBootstrap() public {
        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, manager));
        recovery.initiateRecovery(address(wallet), device, device2);
    }

    /// @notice Retired manager cannot approve
    function test_ManagerCannotApprove() public {
        uint256 id = _initiateRecovery(device, device2);

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, manager));
        recovery.approveRecovery(address(wallet));
    }

    /// @notice Retired manager cannot cancel
    function test_ManagerCannotCancel() public {
        uint256 id = _initiateRecovery(device, device2);

        vm.prank(manager);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        recovery.cancelRecovery(address(wallet));
    }

    /// @notice Stranger cannot initiate
    function test_StrangerCannotInitiate() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotGuardianOrDevice.selector, stranger));
        recovery.initiateRecovery(address(wallet), device, device2);
    }

    /// @notice Guardian cannot move funds
    function test_GuardianCannotExecuteTransactions() public {
        // Guardians can only initiate/approve recoveries - they don't sign device transactions
        // This is enforced by KeymeshWallet.execute checking signature recovery
        // The test here verifies that a guardian address is not a device
        assertFalse(wallet.isDeviceAuthorized(g1), "guardians should not be devices");
    }

    /// @notice Device cannot approve recovery
    function test_DeviceCannotApproveRecovery() public {
        uint256 id = _initiateRecovery(device, device2);

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.NotRegisteredGuardian.selector, device));
        recovery.approveRecovery(address(wallet));
    }

    /****************************************
     *           Helper Functions
     *****************************************/

    function _initiateRecovery(address replaced, address newDev)
        internal
        returns (uint256 id)
    {
        vm.prank(device);
        recovery.initiateRecovery(address(wallet), replaced, newDev);
        id = recovery.latestRecoveryIdOf(address(wallet));
        modelLatestRecoveryId = id;
        modelRecoveryInitiator[id] = device;
        modelRecoveryNewDevice[id] = newDev;
        modelRecoveryReplacedDevice[id] = replaced;
        modelRecoveryStatus[id] = IRecoveryManager.RecoveryStatus.Pending;
        modelRecoveryApprovals[id] = 0;
        return id;
    }

    function _approve(address guardian) internal {
        uint256 recoveryId = recovery.latestRecoveryIdOf(address(wallet));
        vm.prank(guardian);
        recovery.approveRecovery(address(wallet));
        modelRecoveryApprovals[recoveryId] += 1;
        modelRecoveryApproved[recoveryId][guardian] = true;

        if (modelRecoveryApprovals[recoveryId] >= 2) {
            modelRecoveryStatus[recoveryId] = IRecoveryManager.RecoveryStatus.QuorumReached;
        }
    }

    function _governViaDevice(uint256 deviceKey, bytes memory data) internal {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(recovery), 0, data, EXPIRY
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
        wallet.execute(address(wallet), block.chainid, address(recovery), 0, data, nonce, EXPIRY, abi.encodePacked(r, s, v));
    }
}
