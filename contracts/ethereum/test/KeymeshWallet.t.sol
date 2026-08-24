// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {GuardianRegistry} from "../src/GuardianRegistry.sol";
import {RecoveryManager} from "../src/RecoveryManager.sol";
import {KeymeshWallet} from "../src/KeymeshWallet.sol";
import {IKeymeshWallet} from "../src/interfaces/IKeymeshWallet.sol";
import {KeymeshErrors} from "../src/KeymeshErrors.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";

contract Counter {
    uint256 public count;

    function increment() external payable {
        count += 1;
    }
}

contract Reverter {
    error Nope();

    receive() external payable {
        revert Nope();
    }

    function die() external pure {
        revert Nope();
    }
}

/// @notice Routes KeymeshTx calls through an external frame so expectRevert
/// can observe reverts raised by internal-library code.
contract DigestCaller {
    function make(
        address wallet,
        uint256 chainId,
        uint256 nonce,
        address to,
        uint256 value,
        bytes memory data,
        uint256 expiry
    ) external pure returns (bytes32) {
        return KeymeshTx.digest(wallet, chainId, nonce, to, value, data, expiry);
    }
}

/// @notice Phase 1.1 execution + device-management behavior, plus the Phase
/// 1.2 wallet-side recovery wiring (bootstrap-only manager authority).
contract KeymeshWalletTest is Test {
    KeymeshWallet internal wallet;
    Counter internal counter;
    Reverter internal reverter;
    RecoveryManager internal recovery;
    GuardianRegistry internal registry;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;
    uint256 internal constant STRANGER_KEY = 0xFEED;

    address internal device;
    address internal device2;
    address internal stranger;

    uint256 internal constant EXPIRY = 2_000_000_000;

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        stranger = vm.addr(STRANGER_KEY);

        recovery = new RecoveryManager();
        registry = GuardianRegistry(address(recovery.guardianRegistry()));
        // The wallet only needs its nonzero recovery-manager pointer here; the
        // full governance flow is exercised in RecoveryManager.t.sol.
        wallet = new KeymeshWallet(address(this), device, address(recovery));
        counter = new Counter();
        reverter = new Reverter();
        deal(address(wallet), 10 ether);

        // Deterministic timestamp below the standard expiry.
        vm.warp(1_999_000_000);
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    function _digest(uint256 nonce, address to, uint256 value, bytes memory data)
        internal
        view
        returns (bytes32)
    {
        return KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, data, EXPIRY);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _execute(uint256 key, uint256 nonce, address to, uint256 value, bytes memory data)
        internal
    {
        bytes32 d = KeymeshTx.digest(address(wallet), block.chainid, nonce, to, value, data, EXPIRY);
        wallet.execute(
            address(wallet), block.chainid, to, value, data, nonce, EXPIRY, _sign(key, d)
        );
    }

    // ---------------------------------------------------------------
    // success cases
    // ---------------------------------------------------------------

    function test_AuthorizedDeviceExecutesEthTransfer() public {
        uint256 before = device2.balance;

        vm.expectEmit(true, true, true, true);
        emit IKeymeshWallet.TransactionExecuted(0, device, device2, 1 ether, "");
        _execute(DEVICE_KEY, 0, device2, 1 ether, "");

        assertEq(device2.balance, before + 1 ether, "recipient underpaid");
        assertEq(address(wallet).balance, 9 ether);
        assertEq(wallet.getNonce(), 1, "nonce must increment");
        assertTrue(wallet.isDeviceAuthorized(device));
    }

    function test_ZeroValueTransactionSucceeds() public {
        uint256 before = address(wallet).balance;
        _execute(DEVICE_KEY, 0, stranger, 0, "");
        assertEq(address(wallet).balance, before, "zero-value must not move funds");
        assertEq(wallet.getNonce(), 1);
    }

    function test_CalldataExecutionReachesTarget() public {
        assertEq(counter.count(), 0);
        _execute(
            DEVICE_KEY, 0, address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)
        );
        assertEq(counter.count(), 1, "calldata not executed");

        _execute(
            DEVICE_KEY,
            1,
            address(counter),
            0.5 ether,
            abi.encodeWithSelector(Counter.increment.selector)
        );
        assertEq(counter.count(), 2);
        assertEq(address(counter).balance, 0.5 ether);
    }

    function test_MultipleSequentialTransactions() public {
        _execute(DEVICE_KEY, 0, device2, 0.1 ether, "");
        _execute(DEVICE_KEY, 1, device2, 0.2 ether, "");
        _execute(
            DEVICE_KEY, 2, address(counter), 0, abi.encodeWithSelector(Counter.increment.selector)
        );

        assertEq(wallet.getNonce(), 3, "nonces must be sequential");
        assertEq(device2.balance, 0.3 ether);
        assertEq(counter.count(), 1);
    }

    function test_ExpiryBoundaryIsInclusive() public {
        vm.warp(EXPIRY); // now == expiry is still valid
        _execute(DEVICE_KEY, 0, device2, 0, "");
        assertEq(wallet.getNonce(), 1);
    }

    // ---------------------------------------------------------------
    // failure cases
    // ---------------------------------------------------------------

    function test_UnauthorizedDeviceSignatureRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.UnauthorizedDevice.selector, stranger)
        );
        _execute(STRANGER_KEY, 0, device2, 0.1 ether, "");
        assertEq(wallet.getNonce(), 0, "failed attempt must not consume nonce");
    }

    function test_TamperedFieldAfterSigningRejected() public {
        // signature over value = 1 ether, submitted claiming value = 2 ether:
        // the recovered signer becomes an unpredictable non-device address.
        bytes32 d = _digest(0, device2, 1 ether, "");
        bytes memory sig = _sign(DEVICE_KEY, d);

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 2 ether, "", 0, EXPIRY, sig);
        assertEq(wallet.getNonce(), 0);
    }

    function test_SignatureForDifferentDigestRejected() public {
        // well-formed signature, but over an unrelated digest
        bytes memory wrongSig = _sign(DEVICE_KEY, keccak256("unrelated message"));

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 0, "", 0, EXPIRY, wrongSig);
        assertEq(wallet.getNonce(), 0);
    }

    function test_MalformedSignaturesRejected() public {
        bytes memory oneByte = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, uint256(1))
        );
        wallet.execute(address(wallet), block.chainid, device2, 0, "", 0, EXPIRY, oneByte);

        vm.expectRevert(
            abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, uint256(0))
        );
        wallet.execute(address(wallet), block.chainid, device2, 0, "", 0, EXPIRY, hex"");

        assertEq(wallet.getNonce(), 0);
    }

    function test_WrongNonceRejected() public {
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, 0, 5));
        _execute(DEVICE_KEY, 5, device2, 0, "");
        assertEq(wallet.getNonce(), 0);
    }

    function test_ReplayedTransactionRejected() public {
        _execute(DEVICE_KEY, 0, device2, 0.1 ether, "");

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.InvalidNonce.selector, 1, 0));
        _execute(DEVICE_KEY, 0, device2, 0.1 ether, "");

        assertEq(device2.balance, 0.1 ether, "replay must not double-pay");
        assertEq(wallet.getNonce(), 1);
    }

    function test_ExpiredTransactionRejected() public {
        vm.warp(EXPIRY + 1);
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.TransactionExpired.selector, EXPIRY, EXPIRY + 1)
        );
        _execute(DEVICE_KEY, 0, device2, 0, "");
        assertEq(wallet.getNonce(), 0);
    }

    function test_WrongWalletParameterRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.WrongWallet.selector, address(0xBEEF))
        );
        wallet.execute(address(0xBEEF), block.chainid, device2, 0, "", 0, EXPIRY, hex"00");
    }

    function test_SignatureForDifferentWalletRejected() public {
        bytes32 foreignDigest =
            KeymeshTx.digest(address(0xDEAD), block.chainid, 0, device2, 0, "", EXPIRY);
        bytes memory sig = _sign(DEVICE_KEY, foreignDigest);

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 0, "", 0, EXPIRY, sig);
        assertEq(wallet.getNonce(), 0);
    }

    function test_WrongChainParameterRejected() public {
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.WrongChain.selector, 999));
        wallet.execute(address(wallet), 999, device2, 0, "", 0, EXPIRY, hex"00");
    }

    function test_SignatureForDifferentChainRejected() public {
        bytes32 crossChainDigest =
            KeymeshTx.digest(address(wallet), block.chainid + 1, 0, device2, 0, "", EXPIRY);
        bytes memory sig = _sign(DEVICE_KEY, crossChainDigest);

        vm.expectRevert();
        wallet.execute(address(wallet), block.chainid, device2, 0, "", 0, EXPIRY, sig);
        assertEq(wallet.getNonce(), 0);
    }

    // ---------------------------------------------------------------
    // state consistency on failed target (nonce NOT consumed)
    // ---------------------------------------------------------------

    function test_FailedTargetLeavesStateUntouched() public {
        uint256 walletBefore = address(wallet).balance;

        vm.expectRevert();
        _execute(DEVICE_KEY, 0, address(reverter), 1 ether, "");

        assertEq(address(wallet).balance, walletBefore, "funds moved on failed call");
        assertEq(wallet.getNonce(), 0, "failed execution must not consume the nonce");

        // The same signed request may be retried until it succeeds or expires.
        _execute(DEVICE_KEY, 0, device2, 0.5 ether, "");
        assertEq(device2.balance, 0.5 ether);
        assertEq(wallet.getNonce(), 1);
    }

    function test_FailedCalldataLeavesStateUntouched() public {
        vm.expectRevert();
        _execute(DEVICE_KEY, 0, address(reverter), 0, abi.encodeWithSelector(Reverter.die.selector));
        assertEq(wallet.getNonce(), 0);
        assertEq(counter.count(), 0);
    }

    // ---------------------------------------------------------------
    // device management access control
    // ---------------------------------------------------------------

    function test_NonManagerCannotRegister() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.NotDeviceManager.selector, stranger));
        wallet.registerDevice(device2);
    }

    function test_NonManagerNonSelfCannotRevoke() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.NotDeviceManager.selector, stranger));
        wallet.revokeDevice(device);
    }

    function test_ManagerRegistersAndRevokedDeviceLosesAuthority() public {
        wallet.registerDevice(device2);
        assertTrue(wallet.isDeviceAuthorized(device2));
        assertEq(wallet.deviceCount(), 2);

        wallet.revokeDevice(device2);
        assertFalse(wallet.isDeviceAuthorized(device2));

        vm.expectRevert();
        _execute(DEVICE2_KEY, 0, device2, 0, "");
        assertEq(wallet.getNonce(), 0);
    }

    function test_DeviceMayRevokeItself() public {
        wallet.registerDevice(device2);
        vm.prank(device2);
        wallet.revokeDevice(device2);
        assertFalse(wallet.isDeviceAuthorized(device2));
    }

    function test_LastDeviceRemovalBlocked() public {
        vm.expectRevert(IKeymeshWallet.LastDeviceRemoval.selector);
        wallet.revokeDevice(device);

        vm.prank(device);
        vm.expectRevert(IKeymeshWallet.LastDeviceRemoval.selector);
        wallet.revokeDevice(device);

        wallet.registerDevice(device2);
        wallet.revokeDevice(device);
        assertFalse(wallet.isDeviceAuthorized(device));
        assertTrue(wallet.isDeviceAuthorized(device2));
    }

    function test_DoubleRegisterAndUnknownRevoke() public {
        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.AlreadyRegistered.selector, device));
        wallet.registerDevice(device);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.NotRegistered.selector, device2));
        wallet.revokeDevice(device2);

        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        wallet.registerDevice(address(0));
    }
}

/// @notice Phase 1.2: the manager is bootstrap-only and recovery application
/// is restricted to the designated RecoveryManager.
contract KeymeshWalletGovernanceTest is Test {
    KeymeshWallet internal wallet;
    RecoveryManager internal recovery;

    uint256 internal constant DEVICE_KEY = 0xA11CE;
    uint256 internal constant DEVICE2_KEY = 0xB0B;

    address internal device;
    address internal device2;
    address internal guardian1 = address(0x1001);
    address internal guardian2 = address(0x1002);

    function setUp() public {
        device = vm.addr(DEVICE_KEY);
        device2 = vm.addr(DEVICE2_KEY);
        recovery = new RecoveryManager();
        wallet = new KeymeshWallet(address(this), device, address(recovery));
    }

    function _bootstrap() internal {
        address[] memory guardians = new address[](2);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        recovery.bootstrapRecoveryGovernance(address(wallet), guardians, 2, 24 hours);
    }

    function test_ZeroRecoveryManagerAddressRejected() public {
        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        new KeymeshWallet(address(this), device, address(0));
    }

    function test_ManagerAuthorityRetiresAtInitialization() public {
        // Before initialization the manager may still register devices.
        wallet.registerDevice(device2);
        assertTrue(wallet.isDeviceAuthorized(device2));

        _bootstrap();

        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.ManagerAuthorityRetired.selector, address(this))
        );
        wallet.registerDevice(address(0xBEEF));

        vm.prank(device2);
        wallet.revokeDevice(device2); // self-revocation unaffected
        assertFalse(wallet.isDeviceAuthorized(device2));

        // Manager can no longer revoke other devices either.
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.NotDeviceManager.selector, address(this))
        );
        wallet.revokeDevice(device);
    }

    function test_RecoveryApplicationRestrictedToRecoveryManager() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.NotRecoveryManager.selector, address(0xBEEF))
        );
        wallet.applyRecoveredDevice(device, device2);

        vm.prank(address(recovery));
        wallet.applyRecoveredDevice(address(0), device2); // pure addition allowed
        assertTrue(wallet.isDeviceAuthorized(device2));

        vm.prank(address(recovery));
        wallet.applyRecoveredDevice(device2, guardian1); // replacement
        assertFalse(wallet.isDeviceAuthorized(device2));
        assertTrue(wallet.isDeviceAuthorized(guardian1));
    }

    function test_ApplyRecoveredDeviceValidation() public {
        vm.startPrank(address(recovery));

        vm.expectRevert(KeymeshErrors.ZeroAddress.selector);
        wallet.applyRecoveredDevice(device, address(0));

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.AlreadyRegistered.selector, device));
        wallet.applyRecoveredDevice(address(0), device);

        vm.expectRevert(abi.encodeWithSelector(IKeymeshWallet.NotRegistered.selector, device2));
        wallet.applyRecoveredDevice(device2, guardian1);

        vm.stopPrank();
        assertEq(wallet.deviceCount(), 1, "failed applications change nothing");
    }

    function test_InitializationOnlyOnceAndOnlyByRecoveryManager() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(
            abi.encodeWithSelector(IKeymeshWallet.NotRecoveryManager.selector, address(0xBEEF))
        );
        wallet.initializeRecoveryGovernance();

        _bootstrap(); // initializes internally

        vm.prank(address(recovery));
        vm.expectRevert(KeymeshErrors.AlreadyInitialized.selector);
        wallet.initializeRecoveryGovernance();

        assertTrue(wallet.recoveryInitialized());
        assertEq(wallet.recoveryManager(), address(recovery));
        assertEq(wallet.manager(), address(this));
    }

    function test_DeviceSetSurvivesRecoveryApplicationAtomically() public {
        _bootstrap();
        uint256 countBefore = wallet.deviceCount();

        vm.prank(address(recovery));
        wallet.applyRecoveredDevice(device, device2);

        assertEq(wallet.deviceCount(), countBefore, "replacement keeps count stable");
        assertTrue(wallet.isDeviceAuthorized(device2));
        assertFalse(wallet.isDeviceAuthorized(device));
    }
}
