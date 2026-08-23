// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeymeshTx} from "../src/KeymeshTx.sol";

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

/// @notice Cross-language fixtures for the canonical KEYMESH_TX_V1 format.
/// @dev Values are frozen from packages/protocol/src/vectors.ts and must also
///      pass in crates/keymesh-core (src/transaction tests). Any mismatch is
///      a protocol bug, not a test artifact.
contract TransactionDigestTest is Test {
    DigestCaller internal caller;

    function setUp() public {
        caller = new DigestCaller();
    }
    function test_DomainTagMatchesSharedVector() public pure {
        assertEq(
            KeymeshTx.DOMAIN_TAG,
            0x908acdd86e8726216702d8abc211b34ca12c9f1537c7180c55096e1c3be1f405,
            "domain tag drifted from TypeScript/Rust"
        );
    }

    function test_Vector1_EthTransfer() public pure {
        bytes32 digest = KeymeshTx.digest(
            0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
            31337,
            0,
            0x70997970C51812dc3A010C7d01b50e0d17dc79C8,
            1 ether,
            "",
            2000000000
        );
        assertEq(
            digest,
            0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a
        );
    }

    function test_Vector2_ZeroValueCalldata() public pure {
        bytes32 digest = KeymeshTx.digest(
            0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,
            11155111,
            7,
            0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,
            0,
            hex"deadbeefcafebabe0123456789abcdef",
            2000000001
        );
        assertEq(
            digest,
            0x58f52cacdeacc22a70f0e855c44e50b34348984261d9c6954c48d6f895870b58
        );
    }

    function test_Vector3_MainnetShaped() public pure {
        bytes memory data = new bytes(64);
        for (uint256 i = 0; i < 16; ++i) {
            data[i * 4 + 0] = 0xaa;
            data[i * 4 + 1] = 0xbb;
            data[i * 4 + 2] = 0xcc;
            data[i * 4 + 3] = 0xdd;
        }
        bytes32 digest = KeymeshTx.digest(
            0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,
            1,
            42,
            0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc,
            123456789,
            data,
            4102444800
        );
        assertEq(
            digest,
            0x645dc7006dfac3665699314be7d1a4af4f2a502d9b6099b71af0db0d8f1c0a58
        );
    }

    function test_DataTooLargeReverts() public {
        bytes memory oversized = new bytes(KeymeshTx.MAX_DATA_BYTES + 1);
        vm.expectRevert(KeymeshTx.DataTooLarge.selector);
        caller.make(address(1), 1, 0, address(2), 0, oversized, 1);
    }
}
