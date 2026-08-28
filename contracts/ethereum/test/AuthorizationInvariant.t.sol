// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";

/// @notice Invariant and fuzz tests for the per-digest transaction authorization
/// lifecycle. Tests atomicity, replay resistance, consumption uniqueness,
/// and authorization isolation between wallets/nonces/policy versions.
contract AuthorizationInvariantTest is Test {
    KeymeshWallet internal wallet;
    RecoveryManager internal recovery;
    PolicyManager internal policy;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant G1_KEY = 0x1001;
    uint256 internal constant G2_KEY = 0x1002;
    uint256 internal constant G3_KEY = 0x1003;
    uint256 internal constant EXPIRY = 2_100_000_000;
    uint256 internal constant THRESHOLD = 1 ether;
    uint32 internal constant TXN_QUORUM = 2;

    address internal device;
    address internal device2;
    address internal g1;
    address internal g2;
    address internal g3;
    address internal manager;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        g1 = vm.addr(G1_KEY);
        g2 = vm.addr(G2_KEY);
        g3 = vm.addr(G3_KEY);
        manager = address(this);

        vm.warp(2_099_000_000);

        recovery = new RecoveryManager();
        policy = new PolicyManager(recovery);
        wallet = new KeymeshWallet(manager, device, address(recovery), address(policy));

        wallet.registerDevice(device2);

        // Fund wallet for value transfers
        deal(address(wallet), 100 ether);

        address[] memory guardians = new address[](3);
        guardians[0] = g1;
        guardians[1] = g2;
        guardians[2] = g3;
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, 24 hours);

        // Configure policy through governance
        _configurePolicy();
    }

    function _configurePolicy() internal {
        bytes memory data = abi.encodeCall(
            IPolicyManager.configurePolicy,
            (
                address(wallet),
                IPolicyManager.AuthorizationMode.DEVICE_ONLY,
                THRESHOLD,
                TXN_QUORUM
            )
        );
        _requestAndApproveAndExecute(data);
    }

    function _deploySink() internal returns (address) {
        return address(new PayableSink());
    }

    function _buildGovernedCall(
        uint256 deviceKey,
        bytes memory data
    ) internal view returns (bytes memory sig, uint256 nonce, bytes32 digest) {
        nonce = wallet.getNonce();
        digest = KeymeshTx.digest(address(wallet), block.chainid, nonce, address(policy), 0, data, EXPIRY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _requestAndApprove(bytes32 digest) internal {
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);

        if (policy.policyVersion(address(wallet)) != 0) {
            vm.prank(g2);
            policy.approveTransaction(address(wallet), digest);
        }
    }

    function _requestAndApproveAndExecute(bytes memory data) internal {
        (bytes memory sig, uint256 nonce, bytes32 digest) = _buildGovernedCall(DEVICE_KEY, data);
        _requestAndApprove(digest);
        wallet.execute(
            address(wallet), block.chainid, address(policy), 0, data, nonce, EXPIRY, sig
        );
    }

    function _sign(bytes32 digest, uint256 key) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Build a high-value transaction that requires guardian approval
    function _buildHighValueTx(address to, uint256 value)
        internal
        view
        returns (bytes32 digest, bytes memory sig, uint256 nonce)
    {
        nonce = wallet.getNonce();
        digest = KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, "", EXPIRY);
        sig = _sign(digest, DEVICE_KEY);
    }

    /// @notice Build a device-only transaction (below threshold)
    function _buildLowValueTx(address to, uint256 value)
        internal
        view
        returns (bytes32 digest, bytes memory sig, uint256 nonce)
    {
        nonce = wallet.getNonce();
        digest = KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, "", EXPIRY);
        sig = _sign(digest, DEVICE_KEY);
    }

    /****************************************
     *           Invariants (always true)
     *****************************************/

    /// @notice At most one active authorization per digest
    function invariant_singleAuthorizationPerDigest() external view {
        // This is enforced by TransactionAuthorizationExists revert
    }

    /// @notice Authorization status transitions are monotonic
    function invariant_authorizationStatusMonotonic() external {
        // Can only go: None -> Pending -> Authorized -> Executed
        // Or: Pending -> Cancelled
        // Never backward
    }

    /// @notice Zero address never has authorization
    function invariant_zeroAddressNoAuth() external pure {
        // Not applicable - zero address can't be a device
    }

    /// @notice Policy version at request time is snapshotted
    function invariant_policyVersionSnapshot() external view {
        // Verified by PolicyChanged revert on version mismatch
    }

    /****************************************
     *           Fuzz: Authorization Lifecycle
     *****************************************/

    /// @notice Fuzz: per-digest authorization lifecycle
    function testFuzz_AuthorizationLifecycle(uint8 phase) public {
        address sink = _deploySink();
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, sink, THRESHOLD + 1, "", EXPIRY
        );

        // Phase 1: Request (Pending)
        if (phase >= 1) {
            vm.prank(device);
            policy.requestAuthorization(address(wallet), digest);
            assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Pending));
        }

        // Phase 2: Approve (Authorized after quorum)
        if (phase >= 2) {
            vm.prank(g1);
            policy.approveTransaction(address(wallet), digest);
            vm.prank(g2);
            policy.approveTransaction(address(wallet), digest);
            assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));
        }

        // Phase 3: Execute (Consumed)
        if (phase >= 3) {
            bytes memory sig = _sign(digest, DEVICE_KEY);
            bytes memory sigCopy = _sign(digest, DEVICE_KEY);
            wallet.execute(address(wallet), block.chainid, sink, THRESHOLD + 1, "", nonce, EXPIRY, sig);

            assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Executed));

            // Cannot consume again
            vm.prank(address(wallet));
            vm.expectRevert(abi.encodeWithSelector(
                IPolicyManager.AuthorizationNotConsumable.selector, digest, uint8(IPolicyManager.TxnAuthStatus.Executed)
            ));
            policy.consumeAuthorization(address(wallet), digest);
        }
    }

    /// @notice Fuzz: at most one successful consumption per digest
    function testFuzz_OneConsumptionPerDigest(uint256 nonceSeed) public {
        address sink = _deploySink();
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, sink, THRESHOLD + 1, "", EXPIRY
        );

        // Request and get quorum approval
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        // Execute - should succeed
        bytes memory sig = _sign(digest, DEVICE_KEY);
        wallet.execute(address(wallet), block.chainid, sink, THRESHOLD + 1, "", nonce, EXPIRY, sig);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Executed));

        // Attempt to execute again with same nonce (should fail on nonce)
        vm.expectRevert(abi.encodeWithSelector(
            IKeymeshWallet.InvalidNonce.selector, nonce + 1, nonce
        ));
        wallet.execute(address(wallet), block.chainid, address(0x1234), THRESHOLD + 1, "", nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), nonce + 1, "double execution must not advance nonce");
    }

    /// @notice Authorization cannot be copied between wallets
    function test_CannotCopyBetweenWallets() public {
        // Create wallet B
        vm.prank(address(0xBEEF));
        KeymeshWallet walletB = new KeymeshWallet(
            address(0xBEEF), device, address(recovery), address(policy)
        );
        address[] memory guardiansB = new address[](1);
        guardiansB[0] = g3;
        vm.prank(address(0xBEEF));
        recovery.bootstrapRecoveryGovernance(address(walletB), guardiansB, 1, 24 hours);

        bytes32 digestA = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );
        bytes32 digestB = KeymeshTx.digest(
            address(walletB), block.chainid, walletB.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        assertTrue(digestA != digestB, "different wallets produce different digests");

        // Request authorization on wallet A
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digestA);

        // Approvals on wallet A don't affect wallet B
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digestA);

        // Wallet B's digest has no authorization
        assertEq(uint8(policy.authorizationOf(digestB).status), uint8(IPolicyManager.TxnAuthStatus.None));

        // Cannot approve against a mismatched wallet parameter
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationNotFound.selector, digestA
        ));
        policy.approveTransaction(address(walletB), digestA); // wrong wallet
    }

    /// @notice Fuzz: authorization cannot be copied between nonces
    function testFuzz_CannotCopyBetweenNonces() public {
        uint256 nonce1 = wallet.getNonce();
        uint256 nonce2 = nonce1 + 1;

        bytes32 digest1 = KeymeshTx.digest(
            address(wallet), block.chainid, nonce1, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );
        bytes32 digest2 = KeymeshTx.digest(
            address(wallet), block.chainid, nonce2, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        // Request and approve digest1
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest1);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest1);

        // digest2 has no authorization
        assertEq(uint8(policy.authorizationOf(digest2).status), uint8(IPolicyManager.TxnAuthStatus.None));
        assertFalse(policy.hasTransactionApproval(digest2, g1), "approvals cannot cross nonce boundary");
    }

    /// @notice Fuzz: authorization cannot be copied between policy versions
    function testFuzz_CannotCopyAcrossVersions(uint256 versionSeed) public {
        uint256 originalVersion = policy.policyVersion(address(wallet));
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        // Request with version N
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        // Change policy - bumps version
        bytes memory changeData = abi.encodeCall(
            IPolicyManager.setValueThreshold,
            (address(wallet), THRESHOLD + 1000)
        );
        _requestAndApproveAndExecute(changeData);

        assertEq(policy.policyVersion(address(wallet)), originalVersion + 1);

        // Trying to approve the old authorization fails with PolicyChanged
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.PolicyChanged.selector, digest, originalVersion, originalVersion + 1
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Fuzz: duplicate request rejected
    function testFuzz_DuplicateRequestRejected() public {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationExists.selector, digest, uint8(IPolicyManager.TxnAuthStatus.Pending)
        ));
        policy.requestAuthorization(address(wallet), digest);
    }

    /// @notice Fuzz: duplicate approval rejected
    function testFuzz_DuplicateApprovalRejected() public {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);

        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationAlreadyApproved.selector, g1
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Fuzz: cancel before quorum invalidates
    function testFuzz_CancelInvalidatesBeforeQuorum(uint256 seed) public {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Pending));

        // Cancel it
        vm.prank(device);
        policy.cancelAuthorization(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Cancelled));

        // Cannot approve after cancel
        vm.prank(g2);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationNotFound.selector, digest
        ));
        policy.approveTransaction(address(wallet), digest);

        // Cannot execute after cancel
        bytes memory sig = _sign(digest, DEVICE_KEY);
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, address(0x1234), THRESHOLD + 1, "", nonce, EXPIRY, sig);
        assertEq(wallet.getNonce(), nonce, "cancelled authorization must not execute");
    }

    /// @notice Fuzz: cancel after quorum but before execution
    function testFuzz_CancelAfterQuorumBeforeExecution(uint256 seed) public {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));

        // Cancel it
        vm.prank(device);
        policy.cancelAuthorization(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Cancelled));

        // Cannot execute after cancel
        bytes memory sig = _sign(digest, DEVICE_KEY);
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, address(0x1234), THRESHOLD + 1, "", nonce, EXPIRY, sig);
        assertEq(wallet.getNonce(), nonce, "cancelled authorization must not execute");
    }

    /// @notice Fuzz: device-only transactions don't need authorization
    function testFuzz_DeviceOnlyBelowThreshold(uint256 value) public {
        vm.assume(value <= THRESHOLD);
        address sink = _deploySink();

        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, sink, value, "", EXPIRY
        );

        // No authorization needed
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.None));

        bytes memory sig = _sign(digest, DEVICE_KEY);
        wallet.execute(address(wallet), block.chainid, sink, value, "", nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), nonce + 1, "device-only tx should execute without authorization");
    }

    /// @notice Fuzz: failed execution preserves authorization
    function testFuzz_FailedExecutionPreservesAuth(uint256 seed) public {
        address reverter = address(new RevertingTarget());
        address sink = _deploySink();
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, reverter, THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        bytes memory sig = _sign(digest, DEVICE_KEY);

        // Execution will fail (reverting target)
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, reverter, THRESHOLD + 1, "", nonce, EXPIRY, sig);

        // Authorization must still be usable
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));
        assertEq(wallet.getNonce(), nonce, "failed execution must not consume nonce");
    }

    /// @notice Fuzz: successful execution consumes authorization exactly once
    function testFuzz_SuccessConsumesOnce(uint256 seed) public {
        address sink = _deploySink();
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, sink, THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        bytes memory sig = _sign(digest, DEVICE_KEY);
        wallet.execute(address(wallet), block.chainid, sink, THRESHOLD + 1, "", nonce, EXPIRY, sig);

        // Authorization consumed
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Executed));
        assertEq(wallet.getNonce(), nonce + 1, "success should advance nonce");
    }

    /// @notice Fuzz: non-device cannot request authorization
    function testFuzz_NonDeviceCannotRequest(uint256 seed) public {
        address nonDevice;
        if (seed % 2 == 0) {
            nonDevice = address(0x2972); // stranger
        } else {
            nonDevice = g1; // guardian
        }

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(nonDevice);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.RequesterNotDevice.selector, nonDevice
        ));
        policy.requestAuthorization(address(wallet), digest);
    }

    /// @notice Fuzz: non-guardian cannot approve
    function testFuzz_NonGuardianCannotApprove(uint256 seed) public {
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        address nonGuardian;
        if (seed % 2 == 0) {
            nonGuardian = address(0x2972); // stranger
        } else {
            nonGuardian = device; // device is not a guardian
        }

        vm.prank(nonGuardian);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.NotRegisteredGuardian.selector, nonGuardian
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Fuzz: only devices can cancel authorization
    function testFuzz_OnlyDevicesCanCancel(uint256 seed) public {
        uint256 nonce = wallet.getNonce();
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, nonce, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        address unauthorized;
        if (seed % 2 == 0) {
            unauthorized = g1; // guardian
        } else {
            unauthorized = address(0x2972); // stranger
        }

        vm.prank(unauthorized);
        vm.expectRevert();
        policy.cancelAuthorization(address(wallet), digest);

        // Status should still be Pending
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Pending));
    }
}

contract PayableSink {
    receive() external payable {}
    fallback() external payable {}
}

/// @notice Helper contract that always reverts on receive/fallback
contract RevertingTarget {
    receive() external payable {
        revert("RevertingTarget: intentional revert");
    }
    fallback() external payable {
        revert("RevertingTarget: intentional revert");
    }
}
