// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IKeymeshWallet} from "./interfaces/IKeymeshWallet.sol";
import {IGuardianRegistry} from "./interfaces/IGuardianRegistry.sol";
import {IPolicyManager} from "./interfaces/IPolicyManager.sol";
import {IRecoveryManager} from "./interfaces/IRecoveryManager.sol";
import {KeymeshErrors} from "./KeymeshErrors.sol";

/// @title PolicyManager
/// @notice Deterministic transaction authorization policy layer plus
///         guardian transaction authorizations for KeyMesh wallets.
/// @dev Phase 1.3 implementation of docs/protocol/policies.md.
///
///      Authority model (no hidden privileges):
///       - Configuration functions require msg.sender == wallet, i.e. they
///         must be executed through KeymeshWallet.execute with a valid device
///         signature over the canonical digest. Because this contract's own
///         admin selectors are STRUCTURALLY classified DEVICE_PLUS_GUARDIANS,
///         such executions additionally require a guardian-approved
///         transaction authorization for that exact digest. A single device
///         therefore can never weaken policy (anti-downgrade invariant).
///       - The Phase 1.2 bootstrap manager has no role here and is never
///         consulted.
///       - Transaction authorization requests are opened by authorized
///         devices, approved by active guardians of the same wallet, and
///         bound to the exact canonical transaction digest — approvals can
///         never be transferred to a different transaction.
///
///      Versioning: every configuration mutation bumps the wallet's policy
///      version. Requests snapshot the version at request time; approvals and
///      execution both re-check it, so ANY policy change invalidates all
///      pending transaction authorizations (documented semantics).
///
///      Gas notes: classification uses mappings only; the admin-selector
///      check is a fixed-size loop over 6 constants. Restricted sets are
///      bounded (MAX_RESTRICTED_DESTINATIONS / MAX_RESTRICTED_SELECTORS).
///      No unbounded iteration exists on any state-changing path.
contract PolicyManager is IPolicyManager {
    /// Bounded restricted sets keep storage predictable; the limits are
    /// protocol constants, documented in docs/protocol/policies.md.
    uint256 public constant MAX_RESTRICTED_DESTINATIONS = 256;
    uint256 public constant MAX_RESTRICTED_SELECTORS = 64;

    /// Selectors of this contract's mutating functions. Calls to these are
    /// ALWAYS classified DEVICE_PLUS_GUARDIANS (anti-downgrade invariant).
    bytes4 private constant _ADMIN_SELECTOR_CONFIGURE = IPolicyManager.configurePolicy.selector;
    bytes4 private constant _ADMIN_SELECTOR_DEFAULT_MODE = IPolicyManager.setDefaultMode.selector;
    bytes4 private constant _ADMIN_SELECTOR_THRESHOLD = IPolicyManager.setValueThreshold.selector;
    bytes4 private constant _ADMIN_SELECTOR_QUORUM = IPolicyManager.setTransactionQuorum.selector;
    bytes4 private constant _ADMIN_SELECTOR_DESTINATION =
        IPolicyManager.setDestinationRestriction.selector;
    bytes4 private constant _ADMIN_SELECTOR_SELECTOR =
        IPolicyManager.setSelectorRestriction.selector;

    /// The RecoveryManager owning the GuardianRegistry used for guardian
    /// checks; immutable so the trust chain is fixed at deployment.
    IRecoveryManager public immutable recoveryManager;

    mapping(address wallet => PolicyConfig) private _config;
    mapping(address wallet => mapping(address destination => bool)) private _restrictedDestination;
    mapping(address wallet => uint256) private _restrictedDestinationCount;
    mapping(address wallet => mapping(bytes4 selector => bool)) private _restrictedSelector;
    mapping(address wallet => uint256) private _restrictedSelectorCount;

    // Digests are globally unique (the canonical encoding binds wallet,
    // chainId, nonce, to, value, data, expiry), so a flat mapping suffices;
    // the stored wallet field is still verified defensively on every use.
    mapping(bytes32 digest => TxnAuthorization) private _authorization;
    mapping(bytes32 digest => mapping(address guardian => bool)) private _txnApproved;

    constructor(IRecoveryManager recoveryManager_) {
        if (address(recoveryManager_) == address(0)) revert KeymeshErrors.ZeroAddress();
        recoveryManager = recoveryManager_;
    }

    // ---------------------------------------------------------------
    // Modifiers
    // ---------------------------------------------------------------

    modifier onlyWalletContract(address wallet) {
        if (msg.sender != wallet) revert UnauthorizedPolicyUpdate(msg.sender);
        _;
    }

    // ---------------------------------------------------------------
    // Configuration (wallet-governed)
    // ---------------------------------------------------------------

    function configurePolicy(
        address wallet,
        AuthorizationMode defaultMode,
        uint256 valueThreshold,
        uint32 guardianApprovalsRequired
    ) external onlyWalletContract(wallet) {
        if (_config[wallet].version != 0) {
            revert AlreadyConfigured(wallet);
        }
        _validateAndStore(wallet, defaultMode, valueThreshold, guardianApprovalsRequired);
    }

    function setDefaultMode(address wallet, AuthorizationMode mode)
        external
        onlyWalletContract(wallet)
    {
        PolicyConfig memory config = _requireConfigured(wallet);
        _validateAndStore(wallet, mode, config.valueThreshold, config.guardianApprovalsRequired);
        emit DefaultModeUpdated(wallet, mode, config.version + 1);
    }

    function setValueThreshold(address wallet, uint256 threshold)
        external
        onlyWalletContract(wallet)
    {
        PolicyConfig memory config = _requireConfigured(wallet);
        _validateAndStore(wallet, config.defaultMode, threshold, config.guardianApprovalsRequired);
        emit ValueThresholdUpdated(wallet, threshold, config.version + 1);
    }

    function setTransactionQuorum(address wallet, uint32 guardianApprovalsRequired)
        external
        onlyWalletContract(wallet)
    {
        PolicyConfig memory config = _requireConfigured(wallet);
        _validateAndStore(
            wallet, config.defaultMode, config.valueThreshold, guardianApprovalsRequired
        );
        emit TransactionQuorumUpdated(wallet, guardianApprovalsRequired, config.version + 1);
    }

    function setDestinationRestriction(address wallet, address destination, bool restricted)
        external
        onlyWalletContract(wallet)
    {
        PolicyConfig memory config = _requireConfigured(wallet);
        if (destination == address(0)) revert KeymeshErrors.ZeroAddress();
        if (restricted) {
            if (!_restrictedDestination[wallet][destination]) {
                uint256 count = _restrictedDestinationCount[wallet];
                if (count >= MAX_RESTRICTED_DESTINATIONS) {
                    revert RestrictedSetLimit("destination", MAX_RESTRICTED_DESTINATIONS);
                }
                _restrictedDestinationCount[wallet] = count + 1;
                _restrictedDestination[wallet][destination] = true;
            }
        } else {
            if (_restrictedDestination[wallet][destination]) {
                _restrictedDestinationCount[wallet] -= 1;
                delete _restrictedDestination[wallet][destination];
            }
        }
        _bumpVersion(wallet, config);
        emit DestinationPolicyUpdated(wallet, destination, restricted, config.version + 1);
    }

    function setSelectorRestriction(address wallet, bytes4 selector, bool restricted)
        external
        onlyWalletContract(wallet)
    {
        PolicyConfig memory config = _requireConfigured(wallet);
        if (isAdminSelector(selector)) {
            // Removing the structural guardian rule for policy administration
            // would be a silent privilege escalation; refuse explicitly.
            revert KeymeshErrors.Unauthorized();
        }
        if (restricted) {
            if (!_restrictedSelector[wallet][selector]) {
                uint256 count = _restrictedSelectorCount[wallet];
                if (count >= MAX_RESTRICTED_SELECTORS) {
                    revert RestrictedSetLimit("selector", MAX_RESTRICTED_SELECTORS);
                }
                _restrictedSelectorCount[wallet] = count + 1;
                _restrictedSelector[wallet][selector] = true;
            }
        } else {
            if (_restrictedSelector[wallet][selector]) {
                _restrictedSelectorCount[wallet] -= 1;
                delete _restrictedSelector[wallet][selector];
            }
        }
        _bumpVersion(wallet, config);
        emit SelectorPolicyUpdated(wallet, selector, restricted, config.version + 1);
    }

    // ---------------------------------------------------------------
    // Transaction authorization lifecycle
    // ---------------------------------------------------------------

    function requestAuthorization(address wallet, bytes32 digest) external {
        IKeymeshWallet walletContract = IKeymeshWallet(wallet);
        if (!walletContract.recoveryInitialized()) revert KeymeshErrors.NotInitialized();
        if (!walletContract.isDeviceAuthorized(msg.sender)) {
            revert RequesterNotDevice(msg.sender);
        }

        TxnAuthStatus existing = _authorization[digest].status;
        if (existing != TxnAuthStatus.None) {
            revert TransactionAuthorizationExists(digest, existing);
        }

        // Requests may exist for unconfigured wallets (classification is
        // DEVICE_ONLY there, so such requests stay inert until configuration).
        // Bootstrap semantics: an unconfigured wallet has no recorded quorum,
        // so requests clamp to ONE guardian approval minimum -- never zero,
        // otherwise a single guardian could auto-authorize anything.
        PolicyConfig memory config = _config[wallet];
        uint32 approvalsRequired =
            config.guardianApprovalsRequired == 0 ? 1 : config.guardianApprovalsRequired;

        _authorization[digest] = TxnAuthorization({
            wallet: wallet,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            policyVersion: config.version,
            approvals: 0,
            approvalsRequired: approvalsRequired,
            status: TxnAuthStatus.Pending
        });

        emit TransactionAuthorizationRequested(
            digest, wallet, msg.sender, approvalsRequired, config.version
        );
    }

    function approveTransaction(address wallet, bytes32 digest) external {
        TxnAuthorization storage record = _authorization[digest];
        if (record.status != TxnAuthStatus.Pending || record.wallet != wallet) {
            revert TransactionAuthorizationNotFound(digest);
        }
        if (!_guardianRegistry().isGuardian(wallet, msg.sender)) {
            revert NotRegisteredGuardian(msg.sender);
        }
        if (_txnApproved[digest][msg.sender]) {
            revert TransactionAuthorizationAlreadyApproved(msg.sender);
        }
        // Policy-version race semantics: any configuration change after the
        // request invalidates it deterministically.
        if (record.policyVersion != _config[wallet].version) {
            revert PolicyChanged(digest, record.policyVersion, _config[wallet].version);
        }

        _txnApproved[digest][msg.sender] = true;
        unchecked {
            record.approvals += 1;
        }
        emit TransactionAuthorizationApproved(digest, wallet, msg.sender, record.approvals);

        if (record.approvals >= record.approvalsRequired) {
            record.status = TxnAuthStatus.Authorized;
            emit TransactionAuthorizationQuorumReached(digest, wallet);
        }
    }

    function cancelAuthorization(address wallet, bytes32 digest) external {
        if (!IKeymeshWallet(wallet).isDeviceAuthorized(msg.sender)) {
            revert KeymeshErrors.Unauthorized();
        }
        TxnAuthorization storage record = _authorization[digest];
        if (record.status != TxnAuthStatus.Pending && record.status != TxnAuthStatus.Authorized) {
            revert TransactionAuthorizationNotFound(digest);
        }

        record.status = TxnAuthStatus.Cancelled;
        emit TransactionAuthorizationCancelled(digest, wallet, msg.sender);
    }

    function consumeAuthorization(address wallet, bytes32 digest) external {
        // Only the wallet itself may consume, during execute().
        if (msg.sender != wallet) revert UnauthorizedPolicyUpdate(msg.sender);
        TxnAuthorization storage record = _authorization[digest];

        // Precise failure mapping for the execution path:
        //   no record            -> AuthorizationRequired
        //   version mismatch     -> PolicyChanged (pending OR authorized)
        //   Pending              -> InsufficientGuardianApprovals
        //   Cancelled / Executed -> AuthorizationNotConsumable
        if (record.status == TxnAuthStatus.None || record.wallet != wallet) {
            revert AuthorizationRequired(digest);
        }
        if (record.policyVersion != _config[wallet].version) {
            revert PolicyChanged(digest, record.policyVersion, _config[wallet].version);
        }
        if (record.status == TxnAuthStatus.Pending) {
            revert InsufficientGuardianApprovals(digest, record.approvals, record.approvalsRequired);
        }
        if (record.status != TxnAuthStatus.Authorized) {
            revert AuthorizationNotConsumable(digest, record.status);
        }

        // Effects before the wallet performs its external call: the request
        // becomes non-reusable even if execution later re-enters.
        record.status = TxnAuthStatus.Executed;
        emit TransactionAuthorizationExecuted(digest, wallet);
    }

    // ---------------------------------------------------------------
    // Classification
    // ---------------------------------------------------------------

    function evaluateAuthorization(address wallet, address to, uint256 value, bytes calldata data)
        external
        view
        returns (AuthorizationMode)
    {
        PolicyConfig memory config = _config[wallet];

        // 1. Structural anti-downgrade rule — holds EVEN FOR UNCONFIGURED
        //    WALLETS: mutating this contract always requires guardians,
        //    otherwise a single device could configure policy freely.
        if (to == address(this) && data.length >= 4 && isAdminSelector(bytes4(data[:4]))) {
            return AuthorizationMode.DEVICE_PLUS_GUARDIANS;
        }

        // Unconfigured wallets preserve exact Phase 1.1 behavior.
        if (config.version == 0) {
            return AuthorizationMode.DEVICE_ONLY;
        }
        // 2. Explicitly restricted calldata selector.
        if (data.length >= 4 && _restrictedSelector[wallet][bytes4(data[:4])]) {
            return AuthorizationMode.DEVICE_PLUS_GUARDIANS;
        }
        // 3. Restricted destination.
        if (_restrictedDestination[wallet][to]) {
            return AuthorizationMode.DEVICE_PLUS_GUARDIANS;
        }
        // 4. Value threshold (strictly above; boundary documented as
        //    value <= threshold => default rule).
        if (value > config.valueThreshold) {
            return AuthorizationMode.DEVICE_PLUS_GUARDIANS;
        }
        // 5. Wallet default.
        return config.defaultMode;
    }

    // ---------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------

    function policyOf(address wallet) external view returns (PolicyConfig memory) {
        return _config[wallet];
    }

    function policyVersion(address wallet) external view returns (uint64) {
        return _config[wallet].version;
    }

    function isRestrictedDestination(address wallet, address destination)
        external
        view
        returns (bool)
    {
        return _restrictedDestination[wallet][destination];
    }

    function isRestrictedSelector(address wallet, bytes4 selector) external view returns (bool) {
        return _restrictedSelector[wallet][selector];
    }

    function authorizationOf(bytes32 digest) external view returns (TxnAuthorization memory) {
        return _authorization[digest];
    }

    function hasTransactionApproval(bytes32 digest, address guardian) external view returns (bool) {
        return _txnApproved[digest][guardian];
    }

    function isAdminSelector(bytes4 selector) public pure returns (bool) {
        return selector == _ADMIN_SELECTOR_CONFIGURE || selector == _ADMIN_SELECTOR_DEFAULT_MODE
            || selector == _ADMIN_SELECTOR_THRESHOLD || selector == _ADMIN_SELECTOR_QUORUM
            || selector == _ADMIN_SELECTOR_DESTINATION || selector == _ADMIN_SELECTOR_SELECTOR;
    }

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    function _guardianRegistry() internal view returns (IGuardianRegistry) {
        return recoveryManager.guardianRegistry();
    }

    function _requireConfigured(address wallet) internal view returns (PolicyConfig memory config) {
        config = _config[wallet];
        if (config.version == 0) revert NotConfigured(wallet);
    }

    function _validateAndStore(
        address wallet,
        AuthorizationMode defaultMode,
        uint256 valueThreshold,
        uint32 guardianApprovalsRequired
    ) private {
        if (
            defaultMode != AuthorizationMode.DEVICE_ONLY
                && defaultMode != AuthorizationMode.DEVICE_PLUS_GUARDIANS
        ) {
            revert InvalidMode(uint8(defaultMode));
        }
        uint32 guardianCount = uint32(_guardianRegistry().guardianCount(wallet));
        if (guardianApprovalsRequired == 0 || guardianApprovalsRequired > guardianCount) {
            revert InvalidGuardianApprovals(guardianApprovalsRequired, guardianCount);
        }

        PolicyConfig memory config = _config[wallet];
        config.defaultMode = defaultMode;
        config.valueThreshold = valueThreshold;
        config.guardianApprovalsRequired = guardianApprovalsRequired;
        config.version = config.version + 1;
        _config[wallet] = config;

        if (config.version == 1) {
            emit PolicyConfigured(wallet, defaultMode, valueThreshold, guardianApprovalsRequired, 1);
        } else {
            emit PolicyUpdated(wallet, config.version - 1, config.version);
        }
    }

    function _bumpVersion(address wallet, PolicyConfig memory config) private {
        config.version = config.version + 1;
        _config[wallet] = config;
        emit PolicyUpdated(wallet, config.version - 1, config.version);
    }
}
