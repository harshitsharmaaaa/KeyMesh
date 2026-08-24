// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPolicyManager
/// @notice Deterministic transaction authorization policy layer for KeyMesh
///         wallets, plus guardian transaction authorizations.
/// @dev Phase 1.3 separation of concerns:
///
///      Device signing   proves WHO authorized a request.
///      PolicyManager    determines WHAT authorization is required.
///      RecoveryManager  changes WHO controls the wallet.
///
///      A device signature is necessary but not automatically sufficient:
///      every execution is classified against the wallet's policy, and
///      transactions classified DEVICE_PLUS_GUARDIANS additionally require a
///      dedicated transaction authorization approved by the wallet's active
///      guardians, bound to the exact canonical transaction digest.
///
///      Classification precedence (first match wins, documented in
///      docs/protocol/policies.md):
///        1. PolicyManager admin selectors   -> DEVICE_PLUS_GUARDIANS (structural,
///                                              cannot be configured away)
///        2. restricted calldata selector    -> DEVICE_PLUS_GUARDIANS
///        3. restricted destination          -> DEVICE_PLUS_GUARDIANS
///        4. value > valueThreshold          -> DEVICE_PLUS_GUARDIANS
///        5. otherwise                       -> wallet's defaultMode
///      Unconfigured wallets (version 0) classify everything DEVICE_ONLY,
///      preserving exact Phase 1.1 behavior until policy governance is opted in.
interface IPolicyManager {
    /// Authorization modes. Values are part of the protocol surface; future
    /// modes (TSS, MPC) may be appended but MUST NOT be reordered.
    enum AuthorizationMode {
        DEVICE_ONLY, // 0: registered-device signature suffices
        DEVICE_PLUS_GUARDIANS // 1: device signature + guardian-approved
        //    transaction authorization for this digest
    }

    /// Lifecycle of a per-digest transaction authorization.
    enum TxnAuthStatus {
        None, // 0: no request exists for this digest
        Pending, // 1: open, collecting guardian approvals below quorum
        Authorized, // 2: quorum reached under the recorded policy version;
        //    consumable by exactly one execution of this digest
        Executed, // 3: consumed by a successful execution (terminal)
        Cancelled // 4: cancelled by an authorized device (terminal)
    }

    struct PolicyConfig {
        AuthorizationMode defaultMode; // applied when no stronger rule matches
        uint256 valueThreshold; // wei; value > threshold => guardians
        uint32 guardianApprovalsRequired; // quorum snapshot source for requests
        uint64 version; // bumped on every configuration change
    }

    struct TxnAuthorization {
        address wallet;
        address requester; // authorized device that opened the request
        uint64 requestedAt;
        uint64 policyVersion; // config version snapshotted at request time
        uint32 approvals;
        uint32 approvalsRequired; // snapshot taken at request time
        TxnAuthStatus status;
    }

    // ---------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------

    event PolicyConfigured(
        address indexed wallet,
        AuthorizationMode defaultMode,
        uint256 valueThreshold,
        uint32 guardianApprovalsRequired,
        uint64 version
    );
    event PolicyUpdated(
        address indexed wallet, uint64 indexed oldVersion, uint64 indexed newVersion
    );
    event DefaultModeUpdated(address indexed wallet, AuthorizationMode mode, uint64 version);
    event ValueThresholdUpdated(address indexed wallet, uint256 threshold, uint64 version);
    event TransactionQuorumUpdated(
        address indexed wallet, uint32 guardianApprovalsRequired, uint64 version
    );
    event DestinationPolicyUpdated(
        address indexed wallet, address indexed destination, bool restricted, uint64 version
    );
    event SelectorPolicyUpdated(
        address indexed wallet, bytes4 indexed selector, bool restricted, uint64 version
    );
    event TransactionAuthorizationRequested(
        bytes32 indexed digest,
        address indexed wallet,
        address indexed requester,
        uint32 approvalsRequired,
        uint64 policyVersion
    );
    event TransactionAuthorizationApproved(
        bytes32 indexed digest,
        address indexed wallet,
        address indexed guardian,
        uint32 approvalCount
    );
    event TransactionAuthorizationQuorumReached(bytes32 indexed digest, address indexed wallet);
    event TransactionAuthorizationCancelled(
        bytes32 indexed digest, address indexed wallet, address indexed by
    );
    event TransactionAuthorizationExecuted(bytes32 indexed digest, address indexed wallet);

    // ---------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------

    error UnauthorizedPolicyUpdate(address caller);
    error AlreadyConfigured(address wallet);
    error NotConfigured(address wallet);
    error InvalidMode(uint8 mode);
    error InvalidThreshold();
    error InvalidGuardianApprovals(uint32 requested, uint32 guardianCount);
    error RestrictedSetLimit(string kind, uint256 limit);
    error RequesterNotDevice(address caller);
    error NotRegisteredGuardian(address guardian);
    error TransactionAuthorizationExists(bytes32 digest, TxnAuthStatus status);
    error TransactionAuthorizationNotFound(bytes32 digest);
    error AuthorizationRequired(bytes32 digest);
    error InsufficientGuardianApprovals(bytes32 digest, uint32 approvals, uint32 required);
    error TransactionAuthorizationAlreadyApproved(address guardian);
    error PolicyChanged(bytes32 digest, uint64 authorizedUnder, uint64 currentVersion);
    error AuthorizationNotConsumable(bytes32 digest, TxnAuthStatus status);

    // ---------------------------------------------------------------
    // Configuration (wallet-governed: msg.sender MUST be the wallet contract;
    // such calls are structurally classified DEVICE_PLUS_GUARDIANS, so they
    // can only execute with a guardian-approved authorization for their own
    // digest — a single device can never weaken policy alone).
    // ---------------------------------------------------------------

    /// @notice One-time initialization; individual setters require it first.
    function configurePolicy(
        address wallet,
        AuthorizationMode defaultMode,
        uint256 valueThreshold,
        uint32 guardianApprovalsRequired
    ) external;

    function setDefaultMode(address wallet, AuthorizationMode mode) external;

    function setValueThreshold(address wallet, uint256 threshold) external;

    function setTransactionQuorum(address wallet, uint32 guardianApprovalsRequired) external;

    function setDestinationRestriction(address wallet, address destination, bool restricted)
        external;

    function setSelectorRestriction(address wallet, bytes4 selector, bool restricted) external;

    // ---------------------------------------------------------------
    // Transaction authorization lifecycle (per canonical digest)
    // ---------------------------------------------------------------

    /// @notice Opens a guardian authorization request bound to `digest`.
    ///         Callable only by an authorized device of `wallet`.
    function requestAuthorization(address wallet, bytes32 digest) external;

    /// @notice Records the calling guardian's approval (once per digest).
    function approveTransaction(address wallet, bytes32 digest) external;

    /// @notice Cancels a Pending/Authorized request. Authorized devices only.
    function cancelAuthorization(address wallet, bytes32 digest) external;

    /// @notice Consumes an Authorized request. Callable ONLY by the wallet
    ///         contract during execute(), effects-before-interaction.
    function consumeAuthorization(address wallet, bytes32 digest) external;

    // ---------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------

    /// @notice Deterministic classification for a hypothetical transaction.
    function evaluateAuthorization(address wallet, address to, uint256 value, bytes calldata data)
        external
        view
        returns (AuthorizationMode);

    function policyOf(address wallet) external view returns (PolicyConfig memory);

    function policyVersion(address wallet) external view returns (uint64);

    function isRestrictedDestination(address wallet, address destination)
        external
        view
        returns (bool);

    function isRestrictedSelector(address wallet, bytes4 selector) external view returns (bool);

    function authorizationOf(bytes32 digest) external view returns (TxnAuthorization memory);

    function hasTransactionApproval(bytes32 digest, address guardian) external view returns (bool);

    /// @notice True when `selector` mutates policy (structural guardian rule).
    function isAdminSelector(bytes4 selector) external pure returns (bool);
}
