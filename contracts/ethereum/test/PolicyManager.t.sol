// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Counter, Reverter} from "./KeymeshWallet.t.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {IPolicyManager} from "../src/interfaces/IPolicyManager.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";

/// @notice Phase 1.3: deterministic policy classification, versioned policy
/// governance, and the per-digest guardian transaction authorization state
/// machine, integrated with KeymeshWallet.execute.
///
/// Foundry note: every expected-revert test BUILDS its signed execution
/// before arming vm.expectRevert — intermediate view calls (getNonce) would
/// otherwise consume the expectation.
contract PolicyManagerTest is Test {
    struct SignedExecution {
        bytes32 digest;
        uint256 nonce;
        bytes signature;
        address to;
        uint256 value;
        bytes data;
    }

    RecoveryManager internal recovery;
    GuardianRegistry internal registry;
    PolicyManager internal policy;
    KeymeshWallet internal wallet;
    Counter internal counter;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant STRANGER_KEY = 0xFEED;

    uint256 internal constant G1_KEY = 0x1001;
    uint256 internal constant G2_KEY = 0x1002;
    uint256 internal constant G3_KEY = 0x1003;

    address internal device;
    address internal device2;
    address internal stranger;
    address internal g1;
    address internal g2;
    address internal g3;

    uint256 internal constant EXPIRY = 2_100_000_000;
    uint256 internal constant THRESHOLD = 1 ether;
    uint32 internal constant TXN_QUORUM = 2;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);
        g1 = vm.addr(G1_KEY);
        g2 = vm.addr(G2_KEY);
        g3 = vm.addr(G3_KEY);

        vm.warp(2_099_000_000);

        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));
        policy = new PolicyManager(recovery);
        wallet = new KeymeshWallet(address(this), device, address(recovery), address(policy));
        counter = new Counter();
        deal(address(wallet), 100 ether);

        // A second device, registered by the bootstrap manager while that
        // authority still exists (multi-device wallet support).
        wallet.registerDevice(device2);

        _bootstrapGuardians();
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    function _bootstrapGuardians() internal {
        address[] memory guardians = new address[](3);
        guardians[0] = g1;
        guardians[1] = g2;
        guardians[2] = g3;
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, 24 hours);
    }

    function _digestFor(address to, uint256 value, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        return KeymeshTx.digest(
            address(wallet), block.chainid, wallet.getNonce(), to, value, data, EXPIRY
        );
    }

    /// Builds a fully signed execution against the CURRENT nonce. Call this
    /// BEFORE arming vm.expectRevert.
    function _build(uint256 deviceKey, address to, uint256 value, bytes memory data)
        internal
        view
        returns (SignedExecution memory e)
    {
        e.to = to;
        e.value = value;
        e.data = data;
        e.nonce = wallet.getNonce();
        e.digest =
            KeymeshTx.digest(address(wallet), block.chainid, e.nonce, to, value, data, EXPIRY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deviceKey, e.digest);
        e.signature = abi.encodePacked(r, s, v);
    }

    function _submit(SignedExecution memory e) internal {
        wallet.execute({
            wallet: address(wallet),
            chainId: block.chainid,
            to: e.to,
            value: e.value,
            data: e.data,
            nonce: e.nonce,
            expiry: EXPIRY,
            signature: e.signature
        });
    }

    function _signAndExecute(uint256 deviceKey, address to, uint256 value, bytes memory data)
        internal
    {
        SignedExecution memory e = _build(deviceKey, to, value, data);
        _submit(e);
    }

    function _requestAsDevice(bytes32 digest) internal {
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);
    }

    function _approveQuorum(bytes32 digest) internal {
        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        if (policy.authorizationOf(digest).status != IPolicyManager.TxnAuthStatus.Authorized) {
            vm.prank(g2);
            policy.approveTransaction(address(wallet), digest);
        }
    }

    function _requestAndApprove(bytes32 digest) internal {
        _requestAsDevice(digest);
        _approveQuorum(digest);
    }

    /// Configures the policy through the REAL governance path: admin selectors
    /// are structurally DEVICE_PLUS_GUARDIANS, so configuration itself needs a
    /// guardian-approved authorization executed by the wallet.
    function _configurePolicyViaGovernance() internal {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.configurePolicy,
                (
                    address(wallet),
                    IPolicyManager.AuthorizationMode.DEVICE_ONLY,
                    THRESHOLD,
                    TXN_QUORUM
                )
            )
        );
        _requestAndApprove(e.digest);
        _submit(e);
        assertEq(policy.policyVersion(address(wallet)), 1, "configure bumps to v1");
    }

    function _setThresholdViaGovernance(uint256 threshold) internal {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(IPolicyManager.setValueThreshold, (address(wallet), threshold))
        );
        _requestAndApprove(e.digest);
        _submit(e);
    }

    function _restrictDestinationViaGovernance(address destination) internal {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.setDestinationRestriction, (address(wallet), destination, true)
            )
        );
        _requestAndApprove(e.digest);
        _submit(e);
    }

    function _restrictSelectorViaGovernance(bytes4 selector) internal {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(IPolicyManager.setSelectorRestriction, (address(wallet), selector, true))
        );
        _requestAndApprove(e.digest);
        _submit(e);
    }

    modifier configured() {
        _configurePolicyViaGovernance();
        _;
    }

    // ---------------------------------------------------------------
    // unconfigured wallets preserve Phase 1.1 behavior
    // ---------------------------------------------------------------

    function test_UnconfiguredWalletClassifiesDeviceOnly() public view {
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(counter), 5 ether, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY)
        );
        assertEq(policy.policyVersion(address(wallet)), 0);
    }

    function test_UnconfiguredWalletExecutesWithoutAuthorization() public {
        uint256 before = g1.balance;
        _signAndExecute(DEVICE_KEY, g1, 5 ether, "");
        assertEq(g1.balance, before + 5 ether, "device-only execution must work");
        assertEq(wallet.getNonce(), 1);
    }

    // ---------------------------------------------------------------
    // configuration governance
    // ---------------------------------------------------------------

    function test_DirectConfigurationRejected() public {
        vm.prank(device); // even an authorized device EOA, bypassing execute()
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.UnauthorizedPolicyUpdate.selector, device)
        );
        policy.configurePolicy(
            address(wallet), IPolicyManager.AuthorizationMode.DEVICE_ONLY, THRESHOLD, TXN_QUORUM
        );

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.UnauthorizedPolicyUpdate.selector, stranger)
        );
        policy.setValueThreshold(address(wallet), 0);
    }

    function test_GovernedConfigurationRequiresAtLeastOneGuardianApproval() public {
        // Bootstrap semantics: an unconfigured wallet classifies admin calls
        // as DEVICE_PLUS_GUARDIANS (structural rule) and clamps request
        // quorum to a minimum of one guardian -- never zero.
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.configurePolicy,
                (
                    address(wallet),
                    IPolicyManager.AuthorizationMode.DEVICE_ONLY,
                    THRESHOLD,
                    TXN_QUORUM
                )
            )
        );

        _requestAsDevice(e.digest);

        // No approvals yet -> execution must fail with the precise error.
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.InsufficientGuardianApprovals.selector,
                e.digest,
                uint32(0),
                uint32(1)
            )
        );
        _submit(e);
        assertEq(policy.policyVersion(address(wallet)), 0, "nothing applied");
        assertEq(wallet.getNonce(), 0);

        // A single guardian approval satisfies the bootstrap minimum.
        vm.prank(g1);
        policy.approveTransaction(address(wallet), e.digest);
        assertEq(
            uint8(policy.authorizationOf(e.digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Authorized)
        );

        _submit(e);
        assertEq(policy.policyVersion(address(wallet)), 1, "configuration applied");
    }

    function test_DoubleConfigurationRejected() public configured {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.configurePolicy,
                (
                    address(wallet),
                    IPolicyManager.AuthorizationMode.DEVICE_ONLY,
                    THRESHOLD,
                    TXN_QUORUM
                )
            )
        );
        _requestAndApprove(e.digest);
        vm.expectRevert(
            abi.encodeWithSelector(
                IKeymeshWallet.ExecutionFailed.selector,
                abi.encodeWithSelector(IPolicyManager.AlreadyConfigured.selector, address(wallet))
            )
        );
        _submit(e);
    }

    function test_InvalidConfigurationRejected() public {
        vm.startPrank(address(wallet));
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.InvalidGuardianApprovals.selector, uint32(0), uint32(3)
            )
        );
        policy.configurePolicy(
            address(wallet), IPolicyManager.AuthorizationMode.DEVICE_ONLY, THRESHOLD, 0
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.InvalidGuardianApprovals.selector, uint32(4), uint32(3)
            )
        );
        policy.configurePolicy(
            address(wallet), IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS, THRESHOLD, 4
        );
        vm.stopPrank();

        // uint8(2) is not a valid enum value; the argument cannot be typed as
        // the enum without a panic, so exercise it via raw calldata instead.
        (bool ok,) = address(policy)
            .call(
                abi.encodeWithSelector(
                    IPolicyManager.configurePolicy.selector,
                    address(wallet),
                    uint8(2),
                    THRESHOLD,
                    uint32(1)
                )
            );
        assertFalse(ok, "invalid mode must revert");
        assertEq(policy.policyVersion(address(wallet)), 0, "failed config leaves version 0");
    }

    // ---------------------------------------------------------------
    // classification semantics
    // ---------------------------------------------------------------

    function test_ValueBoundaryClassification() public configured {
        address to = address(counter);
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), to, THRESHOLD, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "value == threshold is DEVICE_ONLY (inclusive boundary)"
        );
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), to, THRESHOLD + 1, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "value > threshold requires guardians"
        );
    }

    function test_DefaultModeAppliesWhenNoStrongerRuleMatches() public {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.configurePolicy,
                (
                    address(wallet),
                    IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS,
                    type(uint256).max,
                    TXN_QUORUM
                )
            )
        );
        _requestAndApprove(e.digest);
        _submit(e);

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), g1, 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "default mode applies below threshold"
        );
    }

    function test_RestrictedDestinationClassification() public configured {
        address restrictedAddr = address(0xDEA1);
        assertFalse(policy.isRestrictedDestination(address(wallet), restrictedAddr));

        _restrictDestinationViaGovernance(restrictedAddr);
        assertTrue(policy.isRestrictedDestination(address(wallet), restrictedAddr));

        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), restrictedAddr, 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "restricted destination requires guardians regardless of value"
        );
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(counter), 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "unknown destinations keep default rule"
        );
    }

    function test_RestrictedSelectorClassification() public configured {
        bytes4 target = Counter.increment.selector;
        assertFalse(policy.isRestrictedSelector(address(wallet), target));

        _restrictSelectorViaGovernance(target);
        assertTrue(policy.isRestrictedSelector(address(wallet), target));

        bytes memory callData = abi.encodeWithSelector(Counter.increment.selector);
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(counter), 0, callData)),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "restricted selector requires guardians"
        );
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(counter), 0, "")),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
            "empty calldata has no selector to restrict"
        );
    }

    function test_ShortCalldataSkipsSelectorRules() public configured {
        for (uint256 len = 0; len < 4; ++len) {
            bytes memory shortData = new bytes(len);
            assertEq(
                uint8(
                    policy.evaluateAuthorization(address(wallet), address(counter), 0, shortData)
                ),
                uint8(IPolicyManager.AuthorizationMode.DEVICE_ONLY),
                "calldata shorter than 4 bytes cannot match selector rules"
            );
        }
    }

    function test_AdminSelectorsAreStructurallyGuarded() public configured {
        assertTrue(policy.isAdminSelector(IPolicyManager.setValueThreshold.selector));
        assertTrue(policy.isAdminSelector(IPolicyManager.configurePolicy.selector));
        assertTrue(policy.isAdminSelector(IPolicyManager.setDefaultMode.selector));
        assertTrue(policy.isAdminSelector(IPolicyManager.setTransactionQuorum.selector));
        assertTrue(policy.isAdminSelector(IPolicyManager.setDestinationRestriction.selector));
        assertTrue(policy.isAdminSelector(IPolicyManager.setSelectorRestriction.selector));
        assertFalse(policy.isAdminSelector(Counter.increment.selector));

        bytes memory adminData =
            abi.encodeCall(IPolicyManager.setValueThreshold, (address(wallet), 2 ether));
        assertEq(
            uint8(policy.evaluateAuthorization(address(wallet), address(policy), 0, adminData)),
            uint8(IPolicyManager.AuthorizationMode.DEVICE_PLUS_GUARDIANS),
            "admin selector cannot be downgraded by configuration"
        );
    }

    function test_AdminSelectorRestrictionsCannotBeRemoved() public configured {
        SignedExecution memory e = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.setSelectorRestriction,
                (address(wallet), IPolicyManager.setValueThreshold.selector, true)
            )
        );
        _requestAndApprove(e.digest);
        vm.expectRevert(
            abi.encodeWithSelector(
                IKeymeshWallet.ExecutionFailed.selector,
                abi.encodeWithSelector(KeymeshErrors.Unauthorized.selector)
            )
        );
        _submit(e);
    }

    // ---------------------------------------------------------------
    // execution integration
    // ---------------------------------------------------------------

    function test_HighValueExecutionRequiresAuthorization() public configured {
        uint256 nonceBaseline = wallet.getNonce(); // governed setup already ran
        SignedExecution memory e = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");

        // No request at all.
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.AuthorizationRequired.selector, e.digest)
        );
        _submit(e);
        assertEq(wallet.getNonce(), nonceBaseline, "rejected execution must not consume nonce");

        // A request alone is still not enough.
        _requestAsDevice(e.digest);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.InsufficientGuardianApprovals.selector,
                e.digest,
                uint32(0),
                TXN_QUORUM
            )
        );
        _submit(e);
        assertEq(wallet.getNonce(), nonceBaseline);

        // One approval is still insufficient.
        vm.prank(g1);
        policy.approveTransaction(address(wallet), e.digest);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.InsufficientGuardianApprovals.selector,
                e.digest,
                uint32(1),
                TXN_QUORUM
            )
        );
        _submit(e);

        // Reaching quorum authorizes THIS digest only.
        vm.prank(g2);
        policy.approveTransaction(address(wallet), e.digest);
        assertEq(
            uint8(policy.authorizationOf(e.digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Authorized)
        );

        uint256 before = g1.balance;
        _submit(e);
        assertEq(g1.balance, before + THRESHOLD + 1, "authorized execution succeeds");
        assertEq(wallet.getNonce(), nonceBaseline + 1);

        // Authorization consumed AND nonce advanced: same digest can never
        // execute again (either layer rejects).
        assertEq(
            uint8(policy.authorizationOf(e.digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Executed)
        );
        SignedExecution memory replay = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        assertTrue(replay.digest != e.digest, "new attempt binds a new nonce/digest");
        vm.expectRevert(
            abi.encodeWithSelector(
                IKeymeshWallet.InvalidNonce.selector, uint256(nonceBaseline + 1), uint256(e.nonce)
            )
        );
        _submit(e); // exact same signed payload
    }

    function test_FailedTargetKeepsAuthorizationRetryable() public configured {
        // Same nonce/digest semantics as Phase 1.1: a failing target reverts
        // the whole frame, including authorization consumption, so the signed
        // request stays retryable until it succeeds or expires.
        Reverter revertTarget = new Reverter();
        uint256 nonceBaseline = wallet.getNonce();
        SignedExecution memory e = _build(DEVICE_KEY, address(revertTarget), THRESHOLD + 1, "");
        _requestAndApprove(e.digest);

        for (uint256 attempt = 0; attempt < 2; ++attempt) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IKeymeshWallet.ExecutionFailed.selector,
                    abi.encodeWithSelector(Reverter.Nope.selector)
                )
            );
            _submit(e);

            assertEq(
                uint8(policy.authorizationOf(e.digest).status),
                uint8(IPolicyManager.TxnAuthStatus.Authorized),
                "atomicity: failed execution must not consume authorization"
            );
            assertEq(wallet.getNonce(), nonceBaseline, "failed attempts keep the nonce");
        }
    }

    function test_RestrictedDestinationExecutionFlow() public configured {
        address restrictedAddr = address(0xDEA1);
        _restrictDestinationViaGovernance(restrictedAddr);

        // Zero-value transfer to a restricted destination still needs guardians.
        // (configure + restriction already consumed two governed nonces.)
        assertEq(wallet.getNonce(), 2);
        SignedExecution memory e = _build(DEVICE_KEY, restrictedAddr, 0, "");
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.AuthorizationRequired.selector, e.digest)
        );
        _submit(e);

        _requestAndApprove(e.digest);
        _submit(e);
        assertEq(wallet.getNonce(), 3, "authorized execution consumes exactly one nonce");
    }

    function test_PolicyAdminExecutionConsumesItsOwnAuthorization() public configured {
        uint64 before = policy.policyVersion(address(wallet));
        _setThresholdViaGovernance(2 ether);
        assertEq(policy.policyVersion(address(wallet)), before + 1);
        assertEq(uint256(policy.policyOf(address(wallet)).valueThreshold), 2 ether);
    }

    // ---------------------------------------------------------------
    // request lifecycle & authority
    // ---------------------------------------------------------------

    function test_OnlyAuthorizedDevicesCanRequest() public configured {
        bytes32 digest = _digestFor(address(counter), THRESHOLD + 1, "");

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.RequesterNotDevice.selector, stranger)
        );
        policy.requestAuthorization(address(wallet), digest);

        vm.prank(g1); // guardians are not devices
        vm.expectRevert(abi.encodeWithSelector(IPolicyManager.RequesterNotDevice.selector, g1));
        policy.requestAuthorization(address(wallet), digest);

        address unregistered = vm.addr(0x9999);
        vm.startPrank(unregistered); // key not registered as a device
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.RequesterNotDevice.selector, unregistered)
        );
        policy.requestAuthorization(address(wallet), digest);
        vm.stopPrank();
    }

    function test_DuplicateRequestRejected() public configured {
        bytes32 digest = _digestFor(address(counter), THRESHOLD + 1, "");
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        vm.prank(device);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.TransactionAuthorizationExists.selector,
                digest,
                IPolicyManager.TxnAuthStatus.Pending
            )
        );
        policy.requestAuthorization(address(wallet), digest);
    }

    function test_ApprovalAuthorityAndUniqueness() public configured {
        bytes32 digest = _digestFor(address(counter), THRESHOLD + 1, "");
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digest);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.NotRegisteredGuardian.selector, stranger)
        );
        policy.approveTransaction(address(wallet), digest);

        vm.prank(device);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.NotRegisteredGuardian.selector, device)
        );
        policy.approveTransaction(address(wallet), digest);

        vm.prank(g1);
        policy.approveTransaction(address(wallet), digest);
        assertTrue(policy.hasTransactionApproval(digest, g1));

        vm.prank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.TransactionAuthorizationAlreadyApproved.selector, g1
            )
        );
        policy.approveTransaction(address(wallet), digest);
    }

    function test_ApprovalBoundToExactDigest() public configured {
        bytes32 digestA = _digestFor(address(counter), THRESHOLD + 1, "");
        vm.prank(device);
        policy.requestAuthorization(address(wallet), digestA);

        vm.prank(g1);
        policy.approveTransaction(address(wallet), digestA);
        assertTrue(policy.hasTransactionApproval(digestA, g1));

        // A different transaction (different value => different digest) gains
        // nothing from A's approvals.
        bytes32 digestB = _digestFor(address(g1), THRESHOLD + 2, "");
        assertTrue(digestA != digestB);
        assertEq(
            uint8(policy.authorizationOf(digestB).status), uint8(IPolicyManager.TxnAuthStatus.None)
        );
        assertFalse(policy.hasTransactionApproval(digestB, g1));

        // Approving against a mismatched wallet parameter fails: records are
        // keyed by digest but defensively bound to their own wallet.
        vm.prank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.TransactionAuthorizationNotFound.selector, digestA
            )
        );
        policy.approveTransaction(address(0xBAD), digestA);
    }

    function test_CancelByDevicesOnly() public configured {
        uint256 nonceBaseline = wallet.getNonce();
        SignedExecution memory e = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        _requestAsDevice(e.digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), e.digest);

        vm.prank(g1); // guardians cannot cancel
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        policy.cancelAuthorization(address(wallet), e.digest);

        vm.prank(stranger);
        vm.expectRevert(KeymeshErrors.Unauthorized.selector);
        policy.cancelAuthorization(address(wallet), e.digest);

        // Any authorized device may stop the request...
        vm.prank(device);
        policy.cancelAuthorization(address(wallet), e.digest);
        assertEq(
            uint8(policy.authorizationOf(e.digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Cancelled)
        );

        // ...and a cancelled request cannot be approved or executed.
        vm.prank(g2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.TransactionAuthorizationNotFound.selector, e.digest
            )
        );
        policy.approveTransaction(address(wallet), e.digest);

        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.AuthorizationNotConsumable.selector,
                e.digest,
                IPolicyManager.TxnAuthStatus.Cancelled
            )
        );
        _submit(e);
        assertEq(wallet.getNonce(), nonceBaseline, "cancelled authorization must not execute");
    }

    function test_AuthorizedRequestsRemainCancellableBeforeExecution() public configured {
        uint256 nonceBaseline = wallet.getNonce();
        SignedExecution memory e = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        bytes32 digest = e.digest;
        _requestAndApprove(digest);
        assertEq(
            uint8(policy.authorizationOf(digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Authorized)
        );

        vm.prank(device2); // any authorized device may abort
        policy.cancelAuthorization(address(wallet), digest);

        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.AuthorizationNotConsumable.selector,
                digest,
                IPolicyManager.TxnAuthStatus.Cancelled
            )
        );
        _submit(e);
        assertEq(wallet.getNonce(), nonceBaseline, "cancelled authorization must not execute");
    }

    function test_UnknownDigestOperationsFailCleanly() public configured {
        bytes32 ghost = keccak256("no such request");

        vm.prank(g1);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.TransactionAuthorizationNotFound.selector, ghost)
        );
        policy.approveTransaction(address(wallet), ghost);

        vm.prank(device);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.TransactionAuthorizationNotFound.selector, ghost)
        );
        policy.cancelAuthorization(address(wallet), ghost);

        vm.prank(address(wallet));
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.AuthorizationRequired.selector, ghost)
        );
        policy.consumeAuthorization(address(wallet), ghost);
    }

    // ---------------------------------------------------------------
    // policy versioning & race semantics
    // ---------------------------------------------------------------

    function test_EveryPolicyChangeBumpsVersion() public configured {
        assertEq(policy.policyVersion(address(wallet)), 1);
        _setThresholdViaGovernance(3 ether);
        assertEq(policy.policyVersion(address(wallet)), 2);
        _restrictDestinationViaGovernance(address(0xBEEF));
        assertEq(policy.policyVersion(address(wallet)), 3);
    }

    function test_PolicyChangeInvalidatesPendingAuthorization() public configured {
        SignedExecution memory e = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        _requestAsDevice(e.digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), e.digest);

        // Raise the transaction quorum through governed administration: the
        // transaction stays guardian-gated (value above threshold), but the
        // pending request was created under version 1 and becomes invalid.
        SignedExecution memory change = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(IPolicyManager.setTransactionQuorum, (address(wallet), uint32(3)))
        );
        _requestAndApprove(change.digest);
        _submit(change);
        assertEq(policy.policyVersion(address(wallet)), 2);

        // Further approvals on the stale request fail on the version check...
        vm.prank(g2);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.PolicyChanged.selector, e.digest, uint64(1), uint64(2)
            )
        );
        policy.approveTransaction(address(wallet), e.digest);

        // ...and execution of the ORIGINAL signed payload fails because the
        // governed change itself consumed a nonce: the digest is bound to
        // its nonce, so it can never execute again (defense layer 1), with
        // the version check remaining as defense layer 2.
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, uint256(2), uint256(1))
        );
        _submit(e);
        assertEq(wallet.getNonce(), 2);

        // A freshly signed attempt at the same intent is still guardian-gated
        // and has no authorization of its own.
        SignedExecution memory fresh = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        assertTrue(fresh.digest != e.digest, "fresh attempt binds a fresh nonce");
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyManager.AuthorizationRequired.selector, fresh.digest)
        );
        _submit(fresh);
        assertEq(wallet.getNonce(), 2);
    }

    function test_PolicyChangeInvalidatesApprovedButUnexecutedAuthorization() public configured {
        SignedExecution memory e = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        bytes32 digest = e.digest;
        _requestAndApprove(digest);
        assertEq(
            uint8(policy.authorizationOf(digest).status),
            uint8(IPolicyManager.TxnAuthStatus.Authorized)
        );

        // Restricting a destination bumps the version; the previously
        // authorized digest was created under version N. The governed change
        // itself consumed a nonce, so the old signed payload can never pass
        // the nonce check again (layer 1); the version check is layer 2.
        _restrictDestinationViaGovernance(address(0xFACE));

        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, uint256(2), uint256(1))
        );
        _submit(e);
        assertEq(wallet.getNonce(), 2, "stale authorization must not execute");

        // Direct consumption surfaces the deterministic version error.
        vm.prank(address(wallet));
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolicyManager.PolicyChanged.selector, digest, uint64(1), uint64(2)
            )
        );
        policy.consumeAuthorization(address(wallet), digest);
    }

    function test_UnrelatedWalletPoliciesAreIsolated() public {
        // Second wallet with its own devices/guardians/policy.
        KeymeshWallet walletB =
            new KeymeshWallet(address(this), stranger, address(recovery), address(policy));
        address[] memory guardiansB = new address[](1);
        guardiansB[0] = g3;
        recovery.bootstrapRecoveryGovernance(address(walletB), guardiansB, 1, 24 hours);

        // Wallet B configures its own policy through its own governance path.
        bytes memory data = abi.encodeCall(
            IPolicyManager.configurePolicy,
            (address(walletB), IPolicyManager.AuthorizationMode.DEVICE_ONLY, 0.5 ether, 1)
        );
        SignedExecution memory eb = SignedExecution({
            digest: KeymeshTx.digest(
                address(walletB),
                block.chainid,
                walletB.getNonce(),
                address(policy),
                0,
                data,
                EXPIRY
            ),
            nonce: walletB.getNonce(),
            signature: new bytes(0),
            to: address(policy),
            value: 0,
            data: data
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(STRANGER_KEY, eb.digest);
        eb.signature = abi.encodePacked(r, s, v);

        vm.prank(stranger);
        policy.requestAuthorization(address(walletB), eb.digest);
        vm.prank(g3);
        policy.approveTransaction(address(walletB), eb.digest);
        walletB.execute(
            address(walletB),
            block.chainid,
            eb.to,
            eb.value,
            eb.data,
            eb.nonce,
            EXPIRY,
            eb.signature
        );

        // Isolation checks.
        assertEq(policy.policyVersion(address(wallet)), 0, "wallet A untouched");
        assertEq(policy.policyVersion(address(walletB)), 1);
        assertEq(uint256(policy.policyOf(address(walletB)).valueThreshold), 0.5 ether);
        assertFalse(policy.isRestrictedDestination(address(walletB), address(0)));

        // A's guardians have no power over A<->B boundaries.
        SignedExecution memory ea = _build(DEVICE_KEY, g1, THRESHOLD + 1, "");
        _requestAsDevice(ea.digest);
        vm.prank(g1);
        policy.approveTransaction(address(wallet), ea.digest);
        assertTrue(policy.hasTransactionApproval(ea.digest, g1));
        assertFalse(policy.hasTransactionApproval(ea.digest, g3));
    }

    // ---------------------------------------------------------------
    // bounded restricted sets
    // ---------------------------------------------------------------

    function test_SelectorSetLimitIsBoundedAndReusable() public configured {
        for (uint256 i = 0; i < policy.MAX_RESTRICTED_SELECTORS(); ++i) {
            bytes4 selector = bytes4(uint32(uint256(0xA700 + i)));
            _restrictSelectorViaGovernance(selector);
            assertTrue(policy.isRestrictedSelector(address(wallet), selector));
        }
        assertEq(policy.policyVersion(address(wallet)), 1 + policy.MAX_RESTRICTED_SELECTORS());

        // The set is bounded: one more entry reverts inside governed execution.
        bytes4 extra = bytes4(uint32(0xBEEF));
        SignedExecution memory overflow = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(IPolicyManager.setSelectorRestriction, (address(wallet), extra, true))
        );
        _requestAndApprove(overflow.digest);
        vm.expectRevert(
            abi.encodeWithSelector(
                IKeymeshWallet.ExecutionFailed.selector,
                abi.encodeWithSelector(
                    IPolicyManager.RestrictedSetLimit.selector,
                    "selector",
                    policy.MAX_RESTRICTED_SELECTORS()
                )
            )
        );
        _submit(overflow);

        // Removing frees a slot for a new entry.
        SignedExecution memory removal = _build(
            DEVICE_KEY,
            address(policy),
            0,
            abi.encodeCall(
                IPolicyManager.setSelectorRestriction,
                (address(wallet), bytes4(uint32(uint256(0xA700))), false)
            )
        );
        _requestAndApprove(removal.digest);
        _submit(removal);
        assertFalse(policy.isRestrictedSelector(address(wallet), bytes4(uint32(uint256(0xA700)))));

        _restrictSelectorViaGovernance(extra);
        assertTrue(policy.isRestrictedSelector(address(wallet), extra));
    }
}

