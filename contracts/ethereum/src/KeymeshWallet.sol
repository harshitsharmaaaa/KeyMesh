// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IKeymeshWallet} from "./interfaces/IKeymeshWallet.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title KeymeshWallet
/// @notice Minimal wallet skeleton: device authorization surface only.
/// @dev PROTOTYPE — Phase 1 replaces single-owner control with the protocol
///      model (device signatures + policy thresholds + guardian quorum).
///      Execution is intentionally disabled so this contract cannot move funds.
contract KeymeshWallet is IKeymeshWallet {
    /// @dev Prototype authority; replaced by threshold authorization in Phase 1.
    address public immutable owner;

    mapping(address device => bool) private _authorized;
    uint256 private _deviceCount;

    constructor(address owner_) {
        if (owner_ == address(0)) revert KeymeshErrors.ZeroAddress();
        owner = owner_;
        emit WalletCreated(owner_);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert KeymeshErrors.Unauthorized();
        _;
    }

    function authorizeDevice(address device) external onlyOwner {
        if (device == address(0)) revert KeymeshErrors.ZeroAddress();
        if (_authorized[device]) revert AlreadyAuthorized(device);

        _authorized[device] = true;
        _deviceCount += 1;
        emit DeviceAuthorized(device, uint64(block.timestamp));
    }

    function revokeDevice(address device) external onlyOwner {
        if (!_authorized[device]) revert NotAuthorized(device);

        delete _authorized[device];
        _deviceCount -= 1;
        emit DeviceRevoked(device, uint64(block.timestamp));
    }

    function isDeviceAuthorized(address device) external view returns (bool) {
        return _authorized[device];
    }

    function deviceCount() external view returns (uint256) {
        return _deviceCount;
    }

    /// @inheritdoc IKeymeshWallet
    function execute(address, uint256, bytes calldata) external pure {
        // Deliberately unimplemented: no execution path exists until signature
        // verification and policy enforcement are in place (Phase 1).
        revert ExecutionNotYetImplemented();
    }

    receive() external payable {}
}
