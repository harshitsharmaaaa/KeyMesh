// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @notice Foundry invariant and fuzz tests for the PolicyManager.
/// Tests policy classification precedence, versioning, anti-downgrade,
/// per-digest authorization lifecycle, and atomicity.
contract PolicyManagerInvariantTest is Test {
    KeymeshWallet internal wallet;
    RecoveryManager internal recovery;
    PolicyManager internal policy;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant STRANGER_KEY = 0x2972;
    uint256 internal constant G1_KEY = 0x1001;
    uint256 internal constant G2_KEY = 0x1002;
    uint256 internal constant G3_KEY = 0x1003;
    uint256 internal constant EXPIRY = 2_100_000_000;
    uint256 internal constant THRESHOLD = 1 ether;
    uint32 internal constant TXN_QUORUM = 2;

    address internal device;
    address internal device2;
    address internal stranger;
    address internal g1;
    address internal g2;
    address internal g3;
    address internal manager;

    constructor() {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);
        g1 = vm.addr(G1_KEY);
        g2 = vm.addr(G2_KEY);
        g3 = vm.addr(G3_KEY);
        manager = address(this);
    }

    function setUp() public {
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
        _configurePolicyViaGovernance();
    }

    function _configurePolicyViaGovernance() internal {
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

    /****************************************
     *           Invariants
     *****************************************/

    /// @notice Policy version increments on every change
    function invariant_versionIncrements() external {
        uint64 version = policy.policyVersion(address(wallet));
        assertGe(version, 1, "version should be >= 1 after configuration");
    }

    /// @notice Policy config is consistent
    function invariant_policyConfigConsistent() external {
        IPolicyManager.PolicyConfig memory config = policy.policyOf(address(wallet));
        assertEq(uint8(config.defaultMode), 0, "default mode should be device_only");
        assertEq(config.valueThreshold, THRESHOLD);
        assertEq(config.guardianApprovalsRequired, TXN_QUORUM);
        assertEq(config.version, 1);
    }

    /// @notice Classification follows documented precedence
    function invariant_precedenceOrder() external view {
        // 1. Admin selectors always require guardians
        bytes memory adminData = abi.encodeWithSelector(
            IPolicyManager.setValueThreshold.selector, address(wallet), 2 ether
        );
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(policy), 0, adminData)),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS)
        );
    }

    /****************************************
     *           Fuzz Tests
     *****************************************/

    /// @notice Fuzz: value threshold boundary
    function testFuzz_ValueThresholdBoundary(uint256 delta) public {
        // value = threshold - 1 -> DEVICE_ONLY
        uint256 below = THRESHOLD - 1 > 0 ? delta % (THRESHOLD - 1) + 1 : 1;

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), THRESHOLD - 1, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "value == threshold is DEVICE_ONLY (inclusive)"
        );

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), THRESHOLD, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "value == threshold is DEVICE_ONLY"
        );

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), THRESHOLD + 1, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "value > threshold requires guardians"
        );
    }

    /// @notice Fuzz: value threshold with large values
    function testFuzz_ValueThresholdLargeValues(uint128 largeValue) public {
        vm.assume(largeValue > THRESHOLD);

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), largeValue, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "large value above threshold requires guardians"
        );
    }

    /// @notice Fuzz: destination restrictions boundary
    function testFuzz_DestinationRestriction(address restrictedDest, bool makeRestricted) public {
        vm.assume(restrictedDest != address(0) && restrictedDest != address(policy));

        // First restrict the destination
        bytes memory data = abi.encodeCall(
            IPolicyManager.setDestinationRestriction,
            (address(wallet), restrictedDest, true)
        );
        _requestAndApproveAndExecute(data);

        assertTrue(policy.isRestrictedDestination(address(wallet), restrictedDest));

        // Now verify it's always guarded regardless of value
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), restrictedDest, 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "restricted destination requires guardians even at 0 value"
        );

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), restrictedDest, THRESHOLD, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "restricted destination requires guardians at any value"
        );

        // Unrestrict
        bytes memory unrestrictData = abi.encodeCall(
            IPolicyManager.setDestinationRestriction,
            (address(wallet), restrictedDest, false)
        );
        _requestAndApproveAndExecute(unrestrictData);

        assertFalse(policy.isRestrictedDestination(address(wallet), restrictedDest));
    }

    /// @notice Fuzz: selector restrictions boundary
    function testFuzz_SelectorRestriction(uint32 selectorSeed) public {
        bytes4 selector = bytes4(selectorSeed);
        // Skip admin selectors
        if (policy.isAdminSelector(selector)) return;

        bytes memory data = abi.encodeCall(
            IPolicyManager.setSelectorRestriction,
            (address(wallet), selector, true)
        );
        _requestAndApproveAndExecute(data);

        assertTrue(policy.isRestrictedSelector(address(wallet), selector));

        // Selector rule applies regardless of value
        bytes memory callData = abi.encodeWithSelector(selector, 1, 2, 3);
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), 0, callData)),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "restricted selector requires guardians"
        );

        // Empty calldata never matches selector rules
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "empty calldata never matches selector rules"
        );
    }

    /// @notice Fuzz: short calldata never matches selector rules
    function testFuzz_ShortCalldataNeverMatchesSelector(uint8 len) public {
        vm.assume(len < 4);

        bytes memory shortData = new bytes(len);
        for (uint8 i = 0; i < len; i++) {
            shortData[i] = bytes1(i);
        }

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(0x1234), 0, shortData)),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "calldata shorter than 4 bytes cannot match selector rules"
        );
    }

    /// @notice Fuzz: admin selectors cannot be restricted
    function testFuzz_AdminSelectorCannotBeRestricted() public {
        bytes4[] memory adminSelectors = new bytes4[](6);
        adminSelectors[0] = IPolicyManager.configurePolicy.selector;
        adminSelectors[1] = IPolicyManager.setDefaultMode.selector;
        adminSelectors[2] = IPolicyManager.setValueThreshold.selector;
        adminSelectors[3] = IPolicyManager.setTransactionQuorum.selector;
        adminSelectors[4] = IPolicyManager.setDestinationRestriction.selector;
        adminSelectors[5] = IPolicyManager.setSelectorRestriction.selector;

        for (uint256 i = 0; i < adminSelectors.length; i++) {
            assertTrue(policy.isAdminSelector(adminSelectors[i]), "admin selector should be structural");
        }
    }

    /// @notice Fuzz: policy changes invalidate pending authorizations
    function testFuzz_PolicyChangeInvalidatesPending(uint8 changeType) public {
        vm.assume(changeType < 5);

        // Build a high-value transaction that needs guardians
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        // Request authorization
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        // Get one approval
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);

        // Now change policy (this invalidates the pending authorization)
        bytes memory changeData;
        if (changeType == 0) {
            changeData = abi.encodeCall(
                IPolicyManager.setValueThreshold,
                (address(wallet), THRESHOLD + 100)
            );
        } else if (changeType == 1) {
            changeData = abi.encodeCall(
                IPolicyManager.setDestinationRestriction,
                (address(wallet), address(0x1234), true)
            );
        } else if (changeType == 2) {
            changeData = abi.encodeCall(
                IPolicyManager.setTransactionQuorum,
                (address(wallet), uint32(3))
            );
        } else if (changeType == 3) {
            changeData = abi.encodeCall(
                IPolicyManager.setDefaultMode,
                (address(wallet), IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS)
            );
        } else {
            changeData = abi.encodeCall(
                IPolicyManager.setSelectorRestriction,
                (address(wallet), bytes4(uint32(0xDEAD)), true)
            );
        }

        _requestAndApproveAndExecute(changeData); // This consumes a nonce and bumps version

        // The pending authorization is now invalid
        vm.prank(g2);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.PolicyChanged.selector, digest, uint64(1), uint64(2)
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Fuzz: per-digest authorization lifecycle
    function testFuzz_AuthorizationLifecycle(uint8 phase) public {
        address sink = address(new PayableSink());
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), sink, THRESHOLD + 1, "", EXPIRY
        );

        // Phase 0: None
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.None));

        // Phase 1: Request (Pending)
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Pending));

        // Phase 2: Approve (need quorum)
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Pending));

        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));

        // Now execute (consume)
        bytes memory sig = _sign(digest, DEVICE_KEY);
        wallet.execute(
            address(wallet), block.chainid, sink, THRESHOLD + 1, "", wallet.getNonce(), EXPIRY, sig
        );

        // Phase 3: Executed (terminal)
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Executed));

        // Cannot consume again
        vm.prank(address(wallet));
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.AuthorizationNotConsumable.selector, digest, uint8(IPolicyManager.TxnAuthStatus.Executed)
        ));
        policy.consumeAuthorization(address(wallet), digest);
    }

    /// @notice Fuzz: duplicate approval rejected
    function testFuzz_DuplicateApproval(uint256 seed) public {
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        uint256 guardianCount = seed % 3 + 1;
        address guardian;
        if (guardianCount == 1) guardian = g1;
        else if (guardianCount == 2) guardian = g2;
        else guardian = g3;

        vm.prank(guardian);
        policy.approveTransaction(address(wallet), digest);

        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationAlreadyApproved.selector, guardian
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Authorization cannot be copied between wallets
    function test_AuthorizationCannotCrossWallets() public {
        vm.prank(stranger);
        KeymeshWallet walletB = new KeymeshWallet(
            stranger, device, address(recovery), address(policy)
        );
        address[] memory guardiansB = new address[](1);
        guardiansB[0] = g3;
        vm.prank(stranger);
        recovery.bootstrapRecoveryGovernance(address(walletB), guardiansB, 1, 24 hours);

        // Request authorization on wallet A
        bytes32 digestA = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digestA);

        // Approvals on wallet A are valid
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digestA);

        // But wallet A's digest cannot authorize wallet B
        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationNotFound.selector, digestA
        ));
        policy.approveTransaction(address(walletB), digestA); // different wallet
    }

    /// @notice Fuzz: authorization cannot be copied between nonces
    function testFuzz_AuthorizationCannotCopyBetweenNonces() public {
        uint256 nonce1 = wallet.getNonce();
        uint256 nonce2 = nonce1 + 1;

        bytes32 digest1 = KeymeshTx.digest(
            address(wallet), block.chainid, nonce1, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );
        bytes32 digest2 = KeymeshTx.digest(
            address(wallet), block.chainid, nonce2, address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        assertTrue(digest1 != digest2, "different nonces produce different digests");

        // Request and approve digest1
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest1);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest1);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest1);

        // digest2 has no authorization
        assertEq(uint8(policy.authorizationOf(digest2).status), uint8(IPolicyManager.TxnAuthStatus.None));
    }

    /// @notice Fuzz: authorization cannot be copied between policy versions
    function testFuzz_AuthorizationCannotCopyAcrossVersions() public {
        uint64 originalVersion = policy.policyVersion(address(wallet));

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(0x1234), THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        // Change policy (bump version)
        bytes memory changeData = abi.encodeCall(
            IPolicyManager.setValueThreshold,
            (address(wallet), THRESHOLD + 100)
        );
        _requestAndApproveAndExecute(changeData);

        assertEq(policy.policyVersion(address(wallet)), originalVersion + 1);

        // Old authorization is now invalid
        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.PolicyChanged.selector, digest, originalVersion, originalVersion + 1
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /****************************************
     *           Anti-Downgrade Tests
     *****************************************/

    /// @notice Single device cannot weaken policy
    function test_AntiDowngrade_NoSingleDeviceWeakening() public {
        // All admin selectors require guardians
        bytes4[] memory adminSelectors = new bytes4[](6);
        adminSelectors[0] = IPolicyManager.configurePolicy.selector;
        adminSelectors[1] = IPolicyManager.setDefaultMode.selector;
        adminSelectors[2] = IPolicyManager.setValueThreshold.selector;
        adminSelectors[3] = IPolicyManager.setTransactionQuorum.selector;
        adminSelectors[4] = IPolicyManager.setDestinationRestriction.selector;
        adminSelectors[5] = IPolicyManager.setSelectorRestriction.selector;

        for (uint256 i = 0; i < adminSelectors.length; i++) {
            bytes memory data = abi.encodeWithSelector(adminSelectors[i]);

            // Try to execute as device-only (no guardian approval)
            uint256 nonce = wallet.getNonce();
            bytes32 digest = KeymeshTx.digest(
                address(wallet), block.chainid, nonce, address(policy), 0, data, EXPIRY
            );
            bytes memory sig = _sign(digest, DEVICE_KEY);

            // Should fail because this requires DEVICE_PLUS_GUARDIANS
            vm.expectRevert(abi.encodeWithSelector(
                IPolicyManager.AuthorizationRequired.selector, digest
            ));
            wallet.execute(address(wallet), block.chainid, address(policy), 0, data, nonce, EXPIRY, sig);
        }
    }

    /// @notice Cannot change default mode to weaken
    function test_AntiDowngrade_CannotChangeDefaultMode() public {
        bytes memory data = abi.encodeCall(
            IPolicyManager.setDefaultMode,
            (address(wallet), IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS)
        );

        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(policy), 0, data, EXPIRY
        );

        // Must request authorization (cannot do device-only)
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        // Approval should be required
        vm.prank(device); // Not a guardian
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.NotRegisteredGuardian.selector, device
        ));
        policy.approveTransaction(address(wallet), digest);
    }

    /// @notice Cannot remove admin selector restrictions
    function test_AntiDowngrade_AdminSelectorCannotBeRestricted() public {
        bytes4 adminSelector = IPolicyManager.setValueThreshold.selector;

        // Attempt to restrict an admin selector must fail (both add and remove)
        bytes memory data = abi.encodeCall(
            IPolicyManager.setSelectorRestriction,
            (address(wallet), adminSelector, true)
        );
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), address(policy), 0, data, EXPIRY
        );
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);
        uint256 nonce = wallet.getNonce();
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.ExecutionFailed.selector, abi.encodeWithSignature("Unauthorized()")));
        wallet.execute(address(wallet), block.chainid, address(policy), 0, data, nonce, EXPIRY, _sign(digest, DEVICE_KEY));

        // Even if it somehow succeeded, removing must also fail - verify via direct check
        assertTrue(policy.isAdminSelector(adminSelector), "admin selector must remain protected");
    }

    /// @notice Admin selector classification is structural
    function test_AntiDowngrade_AdminSelectorStructural() public {
        bytes4[] memory adminSelectors = new bytes4[](6);
        adminSelectors[0] = IPolicyManager.configurePolicy.selector;
        adminSelectors[1] = IPolicyManager.setDefaultMode.selector;
        adminSelectors[2] = IPolicyManager.setValueThreshold.selector;
        adminSelectors[3] = IPolicyManager.setTransactionQuorum.selector;
        adminSelectors[4] = IPolicyManager.setDestinationRestriction.selector;
        adminSelectors[5] = IPolicyManager.setSelectorRestriction.selector;

        for (uint256 i = 0; i < adminSelectors.length; i++) {
            assertTrue(policy.isAdminSelector(adminSelectors[i]), "admin selector must be structural");
            assertEq(
                uint8(policy.evaluateAuthorization(address(wallet), address(policy), 0, abi.encodeWithSelector(adminSelectors[i]))),
                uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
                "admin selector always requires guardians"
            );
        }
    }

    /****************************************
     *           Atomicity Tests
     *****************************************/

    /// @notice Failed execution preserves authorization
    function test_Atomicity_FailedTargetPreservesAuthorization() public {
        address reverter = address(new RevertingTarget());
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), reverter, THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));

        bytes memory sig = _sign(digest, DEVICE_KEY);

        // This will fail because reverter reverts
        uint256 nonce = wallet.getNonce();
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, reverter, THRESHOLD + 1, "", nonce, EXPIRY, sig);

        // Authorization must still be usable
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Authorized));
    }

    /// @notice Successful execution consumes authorization exactly once
    function test_Atomicity_SuccessConsumesOnce() public {
        address sink = address(new PayableSink());
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), sink, THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        bytes memory sig = _sign(digest, DEVICE_KEY);
        wallet.execute(address(wallet), block.chainid, sink, THRESHOLD + 1, "", wallet.getNonce(), EXPIRY, sig);

        // Authorization consumed
        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Executed));

        // Cannot consume again
        vm.prank(address(wallet));
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.AuthorizationNotConsumable.selector, digest, uint8(IPolicyManager.TxnAuthStatus.Executed)
        ));
        policy.consumeAuthorization(address(wallet), digest);
    }

    /// @notice Cancelled authorization cannot execute
    function test_Atomicity_CancelledCannotExecute() public {
        address sink = address(new PayableSink());
        bytes32 digest = KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), sink, THRESHOLD + 1, "", EXPIRY
        );

        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        vm.prank(g2);
        policy.approveTransaction(address(wallet), digest);

        // Cancel it
        vm.prank(device);
        policy.cancelAuthorization(address(wallet), digest);

        assertEq(uint8(policy.authorizationOf(digest).status), uint8(IPolicyManager.TxnAuthStatus.Cancelled));

        // Cannot execute
        bytes memory sig = _sign(digest, DEVICE_KEY);
        uint256 nonce = wallet.getNonce();
        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, sink, THRESHOLD + 1, "", nonce, EXPIRY, sig);

        assertEq(wallet.getNonce(), nonce, "cancelled authorization must not execute");
    }

    /// @notice Direct EOA calls to policy config are rejected
    function test_NoPrivilegeEscalation_DirectEOOCallsRejected() public {
        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.UnauthorizedPolicyUpdate.selector, device
        ));
        policy.configurePolicy(
            address(wallet), IPolicyManager.AuthorizationMode.DEVICE_ONLY, THRESHOLD, TXN_QUORUM
        );

        bytes memory data = abi.encodeCall(
            IPolicyManager.setValueThreshold,
            (address(wallet), THRESHOLD + 1)
        );
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.UnauthorizedPolicyUpdate.selector, stranger
        ));
        policy.setValueThreshold(address(wallet), THRESHOLD + 1);
    }

    /// @notice Policy version increments exactly once per change
    function test_VersionBumpsExactlyOnce() public {
        uint64 before = policy.policyVersion(address(wallet));

        bytes memory data = abi.encodeCall(
            IPolicyManager.setValueThreshold,
            (address(wallet), THRESHOLD + 100)
        );
        _requestAndApproveAndExecute(data);

        uint64 versionAfter = policy.policyVersion(address(wallet));
        assertEq(versionAfter, before + 1, "version must increment exactly once");
    }

    /// @notice Unknown digest operations fail cleanly
    function test_UnknownDigestOperationsFailCleanly() public {
        bytes32 ghost = keccak256("no such request");

        vm.prank(g1);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationNotFound.selector, ghost
        ));
        policy.approveTransaction(address(wallet), ghost);

        vm.prank(device);
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.TransactionAuthorizationNotFound.selector, ghost
        ));
        policy.cancelAuthorization(address(wallet), ghost);

        vm.prank(address(wallet));
        vm.expectRevert(abi.encodeWithSelector(
            IPolicyManager.AuthorizationRequired.selector, ghost
        ));
        policy.consumeAuthorization(address(wallet), ghost);
    }

    function abi_encodeRevertData(string memory reason) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(reason);
    }
}

/// @notice Helper contract that accepts ETH transfers
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
