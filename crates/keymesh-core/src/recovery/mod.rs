//! Guardian recovery state machine — reference semantics for the on-chain
//! `RecoveryManager` contract (Phase 1.2).
//!
//! This module mirrors `contracts/ethereum/src/RecoveryManager.sol` exactly:
//! same states, same transitions, same inclusive timelock boundary
//! (`now >= execute_after`), count-based quorum (one guardian = one approval),
//! and snapshot semantics for quorum/timelock captured at initiation.
//!
//! The Rust core is guardian-set agnostic: authorization of WHO may approve or
//! cancel belongs to the caller layer (on-chain that is GuardianRegistry and
//! KeymeshWallet device state). What this module owns is the lifecycle math —
//! pure, deterministic, and injectable-clock tested.
//!
//! Canonical encoding: [`RecoveryRequest::canonical_bytes`] produces a stable,
//! unambiguous byte string for a recovery request (domain-tagged
//! `KEYMESH_RECOVERY_V1`). A future phase can sign these bytes; nothing here
//! performs cryptography itself.

use crate::errors::KeymeshError;
use crate::serialization::Encoder;

/// Lifecycle states, numbered identically to the Solidity enum so encodings
/// stay comparable across languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryStatus {
    /// No request has been initiated (or none exists for the wallet).
    None = 0,
    /// Open request collecting guardian approvals below quorum.
    Pending = 1,
    /// Quorum reached; timelock running until `execute_after`.
    QuorumReached = 2,
    /// Timelock elapsed (`now >= execute_after`); finalizable.
    Executable = 3,
    /// Terminal: executed, devices replaced atomically on-chain.
    Executed = 4,
    /// Terminal: cancelled by an authorized device before execution.
    Cancelled = 5,
}

impl RecoveryStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, RecoveryStatus::Executed | RecoveryStatus::Cancelled)
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            RecoveryStatus::Pending | RecoveryStatus::QuorumReached | RecoveryStatus::Executable
        )
    }

    /// Whether `action` is valid from `self`. Mirrors the contract's revert
    /// conditions one-for-one; used by the exhaustive transition tests.
    pub fn allows(self, action: Action) -> bool {
        match action {
            Action::Approve => self == RecoveryStatus::Pending,
            Action::Cancel => self.is_live(),
            Action::Finalize => {
                // Finalize requires the EFFECTIVE status (Executable); the
                // promotion from QuorumReached happens via `effective_status`.
                self == RecoveryStatus::Executable
            }
            Action::Initiate => !self.is_live(),
        }
    }
}

/// Lifecycle actions tested against every state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Initiate,
    Approve,
    Cancel,
    Finalize,
}

impl std::fmt::Display for RecoveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecoveryStatus::None => "none",
            RecoveryStatus::Pending => "pending",
            RecoveryStatus::QuorumReached => "quorum_reached",
            RecoveryStatus::Executable => "executable",
            RecoveryStatus::Executed => "executed",
            RecoveryStatus::Cancelled => "cancelled",
        };
        write!(f, "{s}")
    }
}

/// Domain tag prefixed to canonical recovery encodings.
pub const DOMAIN: &str = "KEYMESH_RECOVERY_V1";

/// A recovery request aggregate — the Rust mirror of the contract's struct.
///
/// Field order and types intentionally track `RecoveryManager.RecoveryRequest`
/// (see docs/protocol/recovery.md for the mapping table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// Globally unique id (the contract uses a monotonically increasing
    /// counter; ids are never reused).
    pub id: u64,
    /// Address (hex) of the wallet being recovered.
    pub wallet: String,
    /// Address (hex) that opened the request (guardian or device).
    pub initiator: String,
    /// Device to revoke at finalization. `None` models total loss of all
    /// devices: finalization then authorizes without revoking anything.
    pub replaced_device: Option<String>,
    /// Device to authorize at finalization.
    pub new_device: String,
    /// Unix seconds when the request was initiated.
    pub initiated_at: u64,
    /// Unix seconds when finalization becomes legal; set when quorum reached.
    pub execute_after: Option<u64>,
    /// Distinct guardian approvals required (snapshot from wallet config).
    pub quorum_snapshot: u32,
    /// Timelock length applied at quorum time, in seconds (snapshot).
    pub timelock_snapshot_seconds: u64,
    approvals: Vec<String>,
    status: RecoveryStatus,
}

impl RecoveryRequest {
    /// Opens a new request in `Pending`. Validates configuration up front:
    /// quorum must be non-zero and satisfiable by `active_guardian_count`,
    /// and the timelock must meet the protocol minimum (mirrors
    /// `MIN_TIMELOCK` = 1 hour on-chain).
    ///
    /// The argument count intentionally mirrors the on-chain initiation call
    /// one-to-one so reviewers can diff the two; grouping into a struct would
    /// hide that mapping, hence the clippy exemption.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate(
        id: u64,
        wallet: impl Into<String>,
        initiator: impl Into<String>,
        replaced_device: Option<String>,
        new_device: impl Into<String>,
        active_guardian_count: usize,
        quorum_snapshot: u32,
        timelock_snapshot_seconds: u64,
        now_seconds: u64,
    ) -> Result<Self, KeymeshError> {
        let new_device = new_device.into();
        if new_device.is_empty() {
            return Err(KeymeshError::InvalidInput(
                "replacement device must not be empty".into(),
            ));
        }
        if replaced_device.as_deref() == Some(new_device.as_str()) {
            return Err(KeymeshError::InvalidInput(
                "replacement device must differ from the device it replaces".into(),
            ));
        }
        if quorum_snapshot == 0 {
            return Err(KeymeshError::InvalidInput(
                "recovery threshold must be greater than zero".into(),
            ));
        }
        if quorum_snapshot as usize > active_guardian_count {
            return Err(KeymeshError::ThresholdNotMet {
                required: quorum_snapshot as usize,
                actual: active_guardian_count,
            });
        }
        if timelock_snapshot_seconds < MIN_TIMELOCK_SECONDS {
            return Err(KeymeshError::TimelockActive {
                remaining_seconds: MIN_TIMELOCK_SECONDS - timelock_snapshot_seconds,
            });
        }
        Ok(Self {
            id,
            wallet: wallet.into(),
            initiator: initiator.into(),
            replaced_device,
            new_device,
            initiated_at: now_seconds,
            execute_after: None,
            quorum_snapshot,
            timelock_snapshot_seconds,
            approvals: Vec::new(),
            status: RecoveryStatus::Pending,
        })
    }

    pub fn status(&self) -> RecoveryStatus {
        self.status
    }

    /// Status after lazy promotion: a `QuorumReached` request whose timelock
    /// has elapsed reads as `Executable` (inclusive boundary). Pure view.
    pub fn effective_status(&self, now_seconds: u64) -> RecoveryStatus {
        if self.status == RecoveryStatus::QuorumReached {
            if let Some(execute_after) = self.execute_after {
                if now_seconds >= execute_after {
                    return RecoveryStatus::Executable;
                }
            }
        }
        self.status
    }

    pub fn approvals(&self) -> &[String] {
        &self.approvals
    }

    pub fn has_approved(&self, guardian: &str) -> bool {
        self.approvals.iter().any(|a| a == guardian)
    }

    /// Records a guardian approval. Errors mirror the contract reverts:
    /// wrong state, unknown/duplicate guardian handling belongs to the caller,
    /// but duplicate approval within this request always errors.
    ///
    /// When the approval reaches the snapshot quorum the timelock starts.
    pub fn approve(
        &mut self,
        guardian: impl Into<String>,
        now_seconds: u64,
    ) -> Result<(), KeymeshError> {
        if self.status != RecoveryStatus::Pending {
            return Err(KeymeshError::InvalidStateTransition {
                from: self.status.to_string(),
                attempted: "approve".into(),
            });
        }

        let guardian = guardian.into();
        if self.approvals.contains(&guardian) {
            return Err(KeymeshError::DuplicateApproval(guardian));
        }
        self.approvals.push(guardian);

        if self.approvals.len() >= self.quorum_snapshot as usize {
            self.status = RecoveryStatus::QuorumReached;
            self.execute_after = Some(now_seconds + self.timelock_snapshot_seconds);
        }
        Ok(())
    }

    /// Cancels the request from any live state. Terminal states reject.
    pub fn cancel(&mut self) -> Result<(), KeymeshError> {
        if !self.status.allows(Action::Cancel) {
            return Err(KeymeshError::InvalidStateTransition {
                from: self.status.to_string(),
                attempted: "cancel".into(),
            });
        }
        self.status = RecoveryStatus::Cancelled;
        Ok(())
    }

    /// Finalizes once the timelock has fully elapsed. Returns the device
    /// replacement to apply `(replaced, new)` — applying it atomically to the
    /// device set is the wallet's job, exactly as on-chain.
    pub fn finalize(&mut self, now_seconds: u64) -> Result<(Option<String>, String), KeymeshError> {
        match self.effective_status(now_seconds) {
            RecoveryStatus::Executable => {}
            RecoveryStatus::QuorumReached => {
                let execute_after = self
                    .execute_after
                    .expect("execute_after set when QuorumReached");
                return Err(KeymeshError::TimelockActive {
                    remaining_seconds: execute_after.saturating_sub(now_seconds),
                });
            }
            other => {
                return Err(KeymeshError::InvalidStateTransition {
                    from: other.to_string(),
                    attempted: "finalize".into(),
                });
            }
        }
        self.status = RecoveryStatus::Executed;
        Ok((self.replaced_device.clone(), self.new_device.clone()))
    }

    /// Deterministic canonical encoding of the request intent.
    ///
    /// Layout (all integers big-endian):
    /// ```text
    /// domain_tag(32) | version(1) | id(8)
    /// | wallet(len-prefixed bytes) | initiator(len-prefixed)
    /// | replaced_device(len-prefixed, empty = none) | new_device(len-prefixed)
    /// | initiated_at(8) | quorum_snapshot(1) | timelock_snapshot_seconds(8)
    /// ```
    /// Status, execute_after, and approvals are deliberately EXCLUDED: they
    /// change over the life of the request and must never alter its identity.
    /// A future phase can sign these bytes to bind an authorization to exactly
    /// one recovery intent. Quorum is encoded as u8 (max 255 guardians per
    /// wallet in this phase).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.write_raw(&keccakless_domain_tag());
        encoder.write_u8(CANONICAL_VERSION);
        encoder.write_u64(self.id);
        encoder.write_bytes(self.wallet.as_bytes());
        encoder.write_bytes(self.initiator.as_bytes());
        encoder.write_bytes(self.replaced_device.as_deref().unwrap_or("").as_bytes());
        encoder.write_bytes(self.new_device.as_bytes());
        encoder.write_u64(self.initiated_at);
        encoder.write_u8(u8::try_from(self.quorum_snapshot).expect("quorum fits u8"));
        encoder.write_u64(self.timelock_snapshot_seconds);
        encoder.into_bytes()
    }
}

pub const MIN_TIMELOCK_SECONDS: u64 = 3_600; // mirrors MIN_TIMELOCK = 1 hours
const CANONICAL_VERSION: u8 = 1;

/// Placeholder domain tag derivation.
///
/// NOTE(security): this is keccak-256-free SHA-256-free placeholder hashing
/// via a trivial mixing loop ONLY because keymesh-core keeps all real hashing
/// behind the crypto provider boundary. It is deterministic and collision-
/// prone by design; before any signature touches these bytes, replace this
/// with the audited keccak-256 used by `transaction`.
fn keccakless_domain_tag() -> [u8; 32] {
    // FNV-1a over the domain string, expanded into a fixed-width tag.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in DOMAIN.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(&hash.to_be_bytes());
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    const HOUR: u64 = 3_600;
    const WALLET: &str = "0xA11CE";
    const OLD_DEVICE: &str = "0xOLD";
    const NEW_DEVICE: &str = "0xNEW";

    fn request(quorum: u32) -> RecoveryRequest {
        RecoveryRequest::initiate(
            7,
            WALLET,
            "0xGUARD1",
            Some(OLD_DEVICE.to_string()),
            NEW_DEVICE,
            5,
            quorum,
            DAY,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn initiates_into_pending_with_snapshots() {
        let r = request(2);
        assert_eq!(r.status(), RecoveryStatus::Pending);
        assert_eq!(r.quorum_snapshot, 2);
        assert_eq!(r.timelock_snapshot_seconds, DAY);
        assert_eq!(r.execute_after, None);
        assert!(r.approvals().is_empty());
    }

    #[test]
    fn zero_quorum_rejected() {
        assert!(matches!(
            RecoveryRequest::initiate(
                1,
                WALLET,
                "0xG",
                Some(OLD_DEVICE.into()),
                NEW_DEVICE,
                5,
                0,
                DAY,
                0
            ),
            Err(KeymeshError::InvalidInput(_))
        ));
    }

    #[test]
    fn unsatisfiable_quorum_rejected() {
        assert!(matches!(
            RecoveryRequest::initiate(
                1,
                WALLET,
                "0xG",
                Some(OLD_DEVICE.into()),
                NEW_DEVICE,
                1,
                2,
                DAY,
                0
            ),
            Err(KeymeshError::ThresholdNotMet {
                required: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn timelock_below_minimum_rejected() {
        assert!(matches!(
            RecoveryRequest::initiate(
                1,
                WALLET,
                "0xG",
                Some(OLD_DEVICE.into()),
                NEW_DEVICE,
                5,
                1,
                HOUR - 1,
                0
            ),
            Err(KeymeshError::TimelockActive { .. })
        ));
    }

    #[test]
    fn minimum_timelock_boundary_accepted() {
        let r = RecoveryRequest::initiate(
            1,
            WALLET,
            "0xG",
            Some(OLD_DEVICE.into()),
            NEW_DEVICE,
            5,
            1,
            HOUR,
            0,
        )
        .unwrap();
        assert_eq!(r.timelock_snapshot_seconds, HOUR);
    }

    #[test]
    fn identical_replace_and_new_rejected() {
        assert!(matches!(
            RecoveryRequest::initiate(
                1,
                WALLET,
                "0xG",
                Some("0xSAME".into()),
                "0xSAME",
                5,
                1,
                DAY,
                0
            ),
            Err(KeymeshError::InvalidInput(_))
        ));
    }

    #[test]
    fn empty_new_device_rejected() {
        assert!(matches!(
            RecoveryRequest::initiate(1, WALLET, "0xG", Some(OLD_DEVICE.into()), "", 5, 1, DAY, 0),
            Err(KeymeshError::InvalidInput(_))
        ));
    }

    #[test]
    fn quorum_transition_and_timelock_start() {
        let mut r = request(2);
        r.approve("0xG1", 1_100).unwrap();
        assert_eq!(r.status(), RecoveryStatus::Pending);

        r.approve("0xG2", 1_200).unwrap();
        assert_eq!(r.status(), RecoveryStatus::QuorumReached);
        assert_eq!(r.execute_after, Some(1_200 + DAY));
    }

    #[test]
    fn duplicate_approval_errors() {
        let mut r = request(2);
        r.approve("0xG1", 1_000).unwrap();
        assert_eq!(r.approvals().len(), 1);
        match r.approve("0xG1", 1_500) {
            Err(KeymeshError::DuplicateApproval(who)) => assert_eq!(who, "0xG1"),
            other => panic!("expected DuplicateApproval, got {other:?}"),
        }
        assert_eq!(r.approvals().len(), 1, "duplicate must not add");
    }

    #[test]
    fn lazy_promotion_to_executable_is_inclusive() {
        let mut r = request(1);
        r.approve("0xG1", 1_000).unwrap();
        let execute_after = r.execute_after.unwrap();

        assert_eq!(
            r.effective_status(execute_after - 1),
            RecoveryStatus::QuorumReached
        );
        assert_eq!(
            r.effective_status(execute_after),
            RecoveryStatus::Executable,
            "boundary is inclusive: now == execute_after is executable"
        );
        assert_eq!(
            r.effective_status(execute_after + DAY),
            RecoveryStatus::Executable
        );
    }

    #[test]
    fn cannot_finalize_before_timelock_elapses() {
        let mut r = request(1);
        r.approve("0xG1", 1_000).unwrap();
        let execute_after = r.execute_after.unwrap();

        assert!(matches!(
            r.finalize(execute_after - 1),
            Err(KeymeshError::TimelockActive { .. })
        ));
        assert_eq!(r.status(), RecoveryStatus::QuorumReached, "unchanged");

        let (replaced, added) = r.finalize(execute_after).unwrap();
        assert_eq!(replaced.as_deref(), Some(OLD_DEVICE));
        assert_eq!(added, NEW_DEVICE);
        assert_eq!(r.status(), RecoveryStatus::Executed);
    }

    #[test]
    fn total_loss_recovery_adds_without_replacing() {
        let mut r =
            RecoveryRequest::initiate(3, WALLET, "0xGUARD", None, NEW_DEVICE, 5, 1, DAY, 1_000)
                .unwrap();
        r.approve("0xG1", 1_100).unwrap();
        let (replaced, added) = r.finalize(1_100 + DAY).unwrap();
        assert_eq!(replaced, None, "nothing to revoke");
        assert_eq!(added, NEW_DEVICE);
    }

    #[test]
    fn cancel_from_every_live_state() {
        // From Pending.
        let mut r = request(2);
        r.cancel().unwrap();
        assert_eq!(r.status(), RecoveryStatus::Cancelled);

        // From QuorumReached.
        let mut r = request(1);
        r.approve("0xG1", 1_000).unwrap();
        r.cancel().unwrap();
        assert_eq!(r.status(), RecoveryStatus::Cancelled);

        // From Executable (timelock elapsed, not yet finalized).
        let mut r = request(1);
        r.approve("0xG1", 1_000).unwrap();
        let execute_after = r.execute_after.unwrap();
        assert_eq!(
            r.effective_status(execute_after),
            RecoveryStatus::Executable
        );
        r.cancel().unwrap();
        assert_eq!(r.status(), RecoveryStatus::Cancelled);
    }

    #[test]
    fn terminal_states_are_frozen() {
        let mut r = request(1);
        r.approve("0xG1", 1_000).unwrap();
        r.finalize(r.execute_after.unwrap()).unwrap(); // Executed

        assert!(matches!(
            r.finalize(r.execute_after.unwrap()),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
        assert!(matches!(
            r.cancel(),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
        assert!(matches!(
            r.approve("0xG2", 2_000),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));

        let mut r = request(1);
        r.cancel().unwrap();
        assert!(matches!(
            r.finalize(DAY * 100),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
        assert!(matches!(
            r.approve("0xG1", 1_000),
            Err(KeymeshError::InvalidStateTransition { .. })
        ));
    }

    /// Exhaustive transition matrix mirroring §16 of the phase spec.
    #[test]
    fn full_state_action_matrix() {
        // (status, action, allowed?)
        let cases: &[(RecoveryStatus, Action, bool)] = &[
            (RecoveryStatus::None, Action::Initiate, true),
            (RecoveryStatus::None, Action::Approve, false),
            (RecoveryStatus::None, Action::Cancel, false),
            (RecoveryStatus::None, Action::Finalize, false),
            (RecoveryStatus::Pending, Action::Initiate, false),
            (RecoveryStatus::Pending, Action::Approve, true),
            (RecoveryStatus::Pending, Action::Cancel, true),
            (RecoveryStatus::Pending, Action::Finalize, false),
            (RecoveryStatus::QuorumReached, Action::Initiate, false),
            (RecoveryStatus::QuorumReached, Action::Approve, false),
            (RecoveryStatus::QuorumReached, Action::Cancel, true),
            (RecoveryStatus::QuorumReached, Action::Finalize, false), // needs promotion
            (RecoveryStatus::Executable, Action::Initiate, false),
            (RecoveryStatus::Executable, Action::Approve, false),
            (RecoveryStatus::Executable, Action::Cancel, true),
            (RecoveryStatus::Executable, Action::Finalize, true),
            (RecoveryStatus::Executed, Action::Initiate, true),
            (RecoveryStatus::Executed, Action::Approve, false),
            (RecoveryStatus::Executed, Action::Cancel, false),
            (RecoveryStatus::Executed, Action::Finalize, false),
            (RecoveryStatus::Cancelled, Action::Initiate, true),
            (RecoveryStatus::Cancelled, Action::Approve, false),
            (RecoveryStatus::Cancelled, Action::Cancel, false),
            (RecoveryStatus::Cancelled, Action::Finalize, false),
        ];
        for (status, action, allowed) in cases {
            assert_eq!(
                status.allows(*action),
                *allowed,
                "{status:?} should {} {action:?}",
                if *allowed { "allow" } else { "reject" }
            );
        }
    }

    #[test]
    fn canonical_encoding_is_deterministic_and_lifecycle_free() {
        let mut a = request(2);
        a.approve("0xG1", 5_000).unwrap(); // reaches quorum, sets execute_after
        let b = request(2);

        assert_eq!(
            a.canonical_bytes(),
            b.canonical_bytes(),
            "approvals, status, and timelock progress must not affect identity"
        );

        // Same content, different id -> different bytes.
        let mut c = request(2);
        c.id += 1;
        assert_ne!(a.canonical_bytes(), c.canonical_bytes());

        // Fixed shape: 32 tag + 1 ver + 8 id
        //   + len-prefixed strings + 8 initiated_at + 1 quorum + 8 timelock.
        let raw = a.canonical_bytes();
        let string_len = |s: &str| 4 + s.len();
        assert_eq!(
            raw.len(),
            32 + 1
                + 8
                + string_len(&a.wallet)
                + string_len(&a.initiator)
                + string_len(a.replaced_device.as_deref().unwrap_or(""))
                + string_len(&a.new_device)
                + 8
                + 1
                + 8
        );
    }

    #[test]
    fn status_discriminants_match_solidity_enum_order() {
        assert_eq!(RecoveryStatus::None as u8, 0);
        assert_eq!(RecoveryStatus::Pending as u8, 1);
        assert_eq!(RecoveryStatus::QuorumReached as u8, 2);
        assert_eq!(RecoveryStatus::Executable as u8, 3);
        assert_eq!(RecoveryStatus::Executed as u8, 4);
        assert_eq!(RecoveryStatus::Cancelled as u8, 5);
    }
}
