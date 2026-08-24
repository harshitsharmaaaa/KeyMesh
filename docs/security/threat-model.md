# KeyMesh Threat Model

> **Status: living document.** Scope covers the intended protocol; items not
> yet implemented are marked. This document is honest about gaps — treat every
> "not yet" as an open work item, not a footnote.

## Assets to protect

1. **User funds** controlled by KeyMesh wallets.
2. **Device private keys** — authority to authorize normal transactions.
3. **Guardian key material** — ability to initiate/approve recoveries only.
4. **Protocol state integrity** — guardian sets, quorum/timelock config,
   recovery records.
5. **Availability** — the user's ability to always regain control.

## Trust boundaries

```
┌─────────────────┐   ┌───────────────┐   ┌──────────────────────────┐
│ User devices    │   │  Guardians'   │   │ Ethereum chain           │
│  (keys, UI)     │   │  environments │   │ (contracts, trust anchor)│
└────────┬────────┘   └──────┬────────┘   └────────────┬─────────────┘
         │                   │                         │
         └───────────────────┴──────────────┬──────────┘
                                            ▼
┌───────────────────────────────────────────────────────────────────────┐
│      RPC providers / indexing / frontend delivery                     │
└───────────────────────────────────────────────────────────────────────┘
```

## Threats

### T1. Device compromise

**Scenario:** malware or physical theft of an authorized device.
**Impact:** attacker can authorize normal-value transactions immediately.
**Mitigations (Phase 1.2):**
- Guardian quorum + timelock permanently replaces the stolen device:
  `initiate → approvals → timelock → finalize` revokes it on-chain and is
  verified end-to-end on Anvil.
- Any healthy co-owned device or any guardian can open that recovery; any
  healthy device can cancel hostile ones.
- High-value transfers requiring guardian quorum remain design-stage
  (**planned Phase 1.3 policy feature**).
**Residual risk:** small transfers drain before finalization — the recovery
timelock protects ownership, not in-flight funds. Per-device spending velocity
limits remain unimplemented.

### T2. Guardian compromise (up to quorum−1)

**Scenario:** attackers compromise individual guardians' keys.
**Impact:** insufficient alone — quorum counts distinct active guardians, one
approval each (Phase 1.2).
**Limits enforced on-chain:** a compromised guardian cannot approve twice,
cannot cancel recoveries, cannot sign transactions or move funds, and cannot
affect wallets it does not guard (all tested). It may initiate a recovery
request, but without honest co-guardians' approvals the request stays inert
and cancellable.
**Residual risk:** compromised guardians observe recovery activity (no
guardian privacy) and can spam requests that owners must cancel.

### T3. Malicious/colluding guardian majority (within one timelock)

**Scenario:** enough guardians collude to pass a hostile recovery naming an
attacker device.
**Impact:** after the timelock elapses AND someone calls `finalizeRecovery`,
the attacker device becomes authorized → full takeover of future authority.
**Mitigations (Phase 1.2, enforced):**
- Mandatory per-wallet timelock (`>= MIN_TIMELOCK`, public on-chain deadline)
  between quorum and executability; early finalization reverts.
- Every authorized device may cancel at ANY point before execution — including
  during the executable-but-unexecuted window.
- Quorum/timelock are snapshotted at initiation, so mid-flight rule-weakening
  cannot accelerate a hostile request.
- Creating a request authorizes nothing; attackers need real guardian
  cooperation AND silence from all devices until execution lands.
**Residual risk:** if ALL honest guardians withhold approval this never gets
far — but if quorum truly colludes AND no honest device cancels within the
window, takeover succeeds. This is a deliberate, documented trade-off.

### T4. Stolen credentials (dashboard/SDK session)

**Impact:** read access to wallet state; no signing authority (keys never
touch the browser; demo keys are server-side PUBLIC fixtures).
**Not yet applicable:** there is no backend/auth system yet. When one exists:
session isolation, no key material server-side, signed challenge login.

### T5. Replay attacks

**Attack:** reuse a captured authorization to re-execute an action.
**Defenses enforced today:**
- Transactions: canonical digest binds wallet + chainId + sequential nonce;
  replaying a used signature reverts `InvalidNonce` (Phase 1.1).
- Recovery: globally unique monotonic request ids; terminal states reject
  every action; a second `finalizeRecovery` reverts forever (Phase 1.2).
- Cross-wallet/cross-chain reuse fails domain binding (tested both directions).

### T6. Unauthorized recovery initiation

**Attack:** anyone opens a recovery naming their own device.
**Current state (Phase 1.2):** initiation requires being an active guardian of
that wallet OR an authorized device of that wallet; everyone else reverts
(`NotGuardianOrDevice`). A hostile-but-authorized initiation still needs real
guardian approvals plus the full timelock with device-cancellable windows, and
authorizes nothing by itself.

### T7. Transaction manipulation (parameter tampering)

**Attack:** alter recipient/value after signatures or approvals exist.
**Defense:** transaction signatures cover the canonical encoding of the
complete request; recovery requests bind replaced/new devices at initiation
and finalization applies exactly those addresses. Any change produces a new
digest/id and invalidates prior authorizations.

### T8. Signature misuse / cross-protocol replay

**Defense:** the `KEYMESH_TX_V1` domain tag prefixes every transaction digest;
recovery intents carry their own versioned domain in the Rust reference
encoder. Guardians never sign digests that the wallet accepts as transactions
(approvals are plain calls, not signatures), so cross-class replay has no
surface in Phase 1.2.

### T9. Malicious frontend

**Attack:** a tampered dashboard tricks users into approving hostile actions.
**Defenses (design):**
- Approvals and finalizations are verified against contract state, not UI
  claims; the SDK decodes custom errors rather than trusting messages.
- Transaction payloads displayed for approval must be reconstructed from
  on-chain data (planned).
**Today:** the dashboard holds no authority — demo flows run server-side with
PUBLIC local fixture keys against disposable Anvil wallets.

### T10. Compromised RPC provider

**Impact:** censorship, stale reads, gas/nonce manipulation.
**Mitigations (design):** multi-provider fallback, client-side validation of
critical state via events, explicit chain-id in every signed payload.
**Status:** partially mitigated — reads go through viem clients; no fallback
provider logic yet.

### T11. Compromised backend/service

KeyMesh's architecture minimizes backend trust: wallets are smart contracts;
the coordinator (when built) relays but cannot authorize. Any future backend
must be treated as T10-class infrastructure, not a root of trust. Note the
demo routes DO hold fixture keys server-side by design; they are local-test
infrastructure, not custody.

### T12. Key-share leakage (future TSS/MPC)

When threshold signing lands, key shares become long-lived secrets:
shares must never exist unencrypted at rest, zeroization required, refresh
(proactive rotation) planned, and share-compromise detection is an open
research item that will be documented honestly rather than hand-waved.
Guardian recovery governance is deliberately independent of signing keys so
this phase does not require a redesign.

### T13. Insider threats (protocol maintainers)

**Mitigations:** no admin keys in contracts (the bootstrap manager retires
itself at initialization); deterministic builds; published verifiable
releases; no server-side key custody by design. Upgrade paths, if ever added,
must themselves be timelocked and guardian-approved.

### T14. Guardian griefing / availability attack (new in Phase 1.2 review)

**Scenario:** a malicious guardian spams recovery requests to exhaust owner
attention, or devices remove guardians below quorum to disable recovery.
**Mitigations:** one active request per wallet; requests are inert without
approvals and cancellable by devices; removing guardians cannot break an
in-flight recovery (snapshot semantics) but CAN brick future ones — the
device-holder controls this, so it is an owner-action risk, not an external
one.
**Residual risk:** accepted; guardian reputation/monitoring is out of scope
for Phase 1.2.

## Out of scope

- Compromise of the Ethereum consensus layer itself.
- Coercion ("$5 wrench") attacks beyond what timelocks already impose.
- Guardian endpoint security (each guardian owns their own hygiene).
- Privacy/confidentiality of transaction contents (public chain).

## Review cadence

Revisit this document whenever: a new contract deploys, the signing stack
changes, a new chain adapter lands, or a dependency with privilege changes.
