# KeyMesh Threat Model

> **Status: living document, initial version.** Scope covers the intended
> protocol; items not yet implemented are marked. This document is honest
> about gaps — treat every "not yet" as an open work item, not a footnote.

## Assets to protect

1. **User funds** controlled by KeyMesh wallets.
2. **Device private keys** — authority to authorize normal transactions.
3. **Guardian key material** — ability to approve recoveries/high-value actions.
4. **Protocol state integrity** — guardian sets, policies, recovery records.
5. **Availability** — the user's ability to always regain control.

## Trust boundaries

```
┌──────────────┐   ┌──────────────┐   ┌───────────────────────────┐
│ User devices │   │  Guardians'  │   │ Ethereum chain (contracts)│
│  (keys, UI)  │   │  environments│   │  trust anchor             │
└──────┬───────┘   └──────┬───────┘   └────────────▲────────────┘
       │                  │                        │
       ▼                  ▼                        │
┌─────────────────────────────────────────────────┴────────────┐
│            RPC providers / indexing / frontend delivery      │
└──────────────────────────────────────────────────────────────┘
```

## Threats

### T1. Device compromise

**Scenario:** malware or physical theft of an authorized device.
**Impact:** attacker can authorize normal-value transactions immediately.
**Mitigations:**
- High-value transfers require guardian quorum regardless of device status.
- Device revocation is immediate and does not require the stolen device.
- Policies can lower the high-value boundary for stricter wallets.
**Residual risk:** small transfers drain before revocation. Not yet mitigated:
per-device spending velocity limits (**planned phase-1 policy feature**).

### T2. Guardian compromise (up to quorum−1)

**Scenario:** attackers compromise individual guardians' keys.
**Impact:** insufficient alone — approvals are weighted and threshold-gated.
**Residual risk:** compromised guardians still *observe* sensitive activity;
guardian privacy is not provided in this design.

### T3. Malicious/colluding guardian majority (within one timelock)

**Scenario:** enough guardian weight colludes to pass a hostile recovery.
**Impact:** recovery completes after the timelock → full wallet takeover.
**Mitigations:**
- Mandatory ≥7-day timelock with public on-chain state.
- Any active guardian may cancel during the window.
- Management timelocks make silent rule-weakening slow and visible.
**Residual risk:** if ALL honest guardians are absent/asleep for the whole
window AND the user never checks, takeover succeeds. This is a deliberate,
documented trade-off between recovery availability and theft resistance.

### T4. Stolen credentials (dashboard/SDK session)

**Impact:** read access to wallet state; no signing authority (keys never
touch the dashboard).
**Not yet applicable:** there is no backend/auth system yet. When one exists:
session isolation, no key material server-side, signed challenge login.

### T5. Replay attacks

**Attack:** reuse a captured signature to re-execute an action.
**Design defenses (enforcement in phase-1):**
- Domain-separated signing payloads (`KEYMESH/tx-auth/v1`, etc.).
- Unique request ids + expiry timestamps in every authorization record.
- Contract-side consumed-request tracking planned before mainnet usage.
**Status today:** request model carries ids/expiries; signature verification
does not exist yet, so replay is impossible only because signing is.

### T6. Unauthorized recovery initiation

**Attack:** anyone opens a recovery naming their own device.
**Current state:** the contract skeleton permits permissionless initiation
(**explicit TODO**). Mitigations already present: quorum + timelock +
cancellation. Phase 1 restricts initiation to owner/wallet devices.

### T7. Transaction manipulation (parameter tampering)

**Attack:** alter recipient/value after approvals are collected.
**Defense:** signatures cover the canonical encoding of the complete request
(canonical serialization is implemented in the Rust core); any field change
invalidates prior approvals because request ids change.
**Status:** canonical encoding implemented and tested; binding signatures to
requests arrives with real signing.

### T8. Signature misuse / cross-protocol replay

**Defense:** domain-separated payload prefixes per action class and versioned
domain strings. The mock crypto provider is clearly labeled insecure; no real
signing exists yet, so misuse surfaces cannot be exercised either.

### T9. Malicious frontend

**Attack:** a tampered dashboard tricks users into approving hostile actions.
**Defenses (design):**
- Approvals are verified against contract state, not UI claims.
- Transaction payloads displayed for approval must be reconstructed from
  on-chain data (planned).
**Today:** dashboard is mock-only and holds no authority — it literally cannot
move anything. This limitation is also why it is safe.

### T10. Compromised RPC provider

**Impact:** censorship, stale reads, gas/nonce manipulation.
**Mitigations (design):** multi-provider fallback, client-side validation of
critical state via events, explicit chain-id in every signed payload.
**Status:** not implemented; SDK has no network layer yet.

### T11. Compromised backend/service

KeyMesh's architecture minimizes backend trust: wallets are smart contracts;
the coordinator (when built) relays but cannot authorize. Any future backend
must be treated as T10-class infrastructure, not a root of trust.

### T12. Key-share leakage (phase-2 TSS/MPC)

When threshold signing lands, key shares become long-lived secrets:
shares must never exist unencrypted at rest, zeroization required, refresh
(proactive rotation) planned, and share-compromise detection is an open
research item that will be documented honestly rather than hand-waved.

### T13. Insider threats (protocol maintainers)

**Mitigations:** no admin keys in contracts; deterministic builds; published
verifiable releases; no server-side key custody by design. Upgrade paths, if
ever added, must themselves be timelocked and guardian-approved.

## Out of scope

- Compromise of the Ethereum consensus layer itself.
- Coercion ("$5 wrench") attacks beyond what timelocks already impose.
- Guardian endpoint security (each guardian owns their own hygiene).
- Privacy/confidentiality of transaction contents (public chain).

## Review cadence

Revisit this document whenever: a new contract deploys, the signing stack
changes, a new chain adapter lands, or a dependency with privilege changes.
