// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";

/// @title TSSPrototypeTest
/// @notice Verifies that the Phase 2.2 threshold prototype's output is a
///         standard ECDSA signature recoverable via ECDSA.recover — without
///         modifying KeymeshWallet.
/// @dev Vector is deterministic via seeded DKG (seed 0xdeadbeefcafe1234):
///      GROUP_ADDRESS=0x427ece1007f57931810ff88cc06399ffce685560
///      DIGEST (vector 1 eth-transfer) = 0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a
///      R=0x2c591d959b1c165a0f1dbb8199423e7a9b7ac6b73093fe66b2ea2c59660c09b0
///      S=0x3542e3dffa74f4ed11fed3aad0b95681ea0ceed471b2ae43b495e4189ac73269
///      V=27  (low-s, valid)
contract TSSPrototypeTest is Test {
    // Deterministic prototype vector — pinned for cross-language verification.
    bytes32 constant DIGEST = 0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a;
    address constant EXPECTED_SIGNER = 0x427EcE1007f57931810ff88cc06399FfcE685560;
    bytes32 constant R = 0x2c591d959b1c165a0f1dbb8199423e7a9b7ac6b73093fe66b2ea2c59660c09b0;
    bytes32 constant S = 0x3542e3dffa74f4ed11fed3aad0b95681ea0ceed471b2ae43b495e4189ac73269;
    uint8 constant V = 27;

    function test_TSSPrototype_RecoversGroupAddress() public pure {
        bytes memory sig = abi.encodePacked(R, S, V);
        address recovered = ECDSA.recover(DIGEST, sig);
        assertEq(recovered, EXPECTED_SIGNER, "TSS sig must recover to group address");
    }

    function test_TSSPrototype_LowS() public pure {
        // secp256k1n/2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
        bytes32 halfN = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
        assertTrue(uint256(S) <= uint256(halfN), "s must be low");
    }

    function test_TSSPrototype_DigestMatchesKeymeshTx() public pure {
        // Prove the digest is the real KEYMESH_TX_V1 eth-transfer vector (cross-language)
        bytes32 d = KeymeshTx.digest(
            0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
            31337,
            0,
            0x70997970C51812dc3A010C7d01b50e0d17dc79C8,
            1 ether,
            "",
            2000000000
        );
        assertEq(d, DIGEST, "digest must be KEYMESH_TX_V1 vector 1");
    }

    function test_TSSPrototype_WrongDigestFails() public pure {
        bytes32 wrong = bytes32(uint256(DIGEST) ^ 1);
        bytes memory sig = abi.encodePacked(R, S, V);
        address recovered = ECDSA.recover(wrong, sig);
        assertTrue(recovered != EXPECTED_SIGNER, "wrong digest must not recover to group");
    }
}
