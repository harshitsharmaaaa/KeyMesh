# Transaction Authorization Policy

> **Status: design + prototype.** Policy evaluation is implemented (pure
> functions) in `crates/keymesh-core/src/policy` and mirrored in
> `packages/protocol/src/policy`. On-chain storage/enforcement is a skeleton in
> `contracts/ethereum/src/PolicyManager.sol`.

## Transaction classes

| Class                | Required authority                        | Timelock |
| -------------------- | ----------------------------------------- | -------- |
| `Normal`             | device signature                          | none     |
| `HighValue`          | device signature + guardian quorum        | none     |
| `GuardianManagement` | device signature + guardian quorum        | 24h      |
| `PolicyUpdate`       | device signature + guardian quorum        | 48h      |
| `Recovery`           | guardian threshold                        | ≥ 7 days |

Rationale:

- **Normal** must stay frictionless — that is the point of device wallets.
- **HighValue** adds human latency exactly where theft impact concentrates.
- **Management** operations are timelocked because they change *who can
  approve future actions*; changing the rules should be slower than using them.
- **Recovery** has the longest window because it transfers complete control.

## Classification

A transfer is high-value when its value meets or exceeds the wallet's
`highValueWeiBoundary` (default: 1 ETH in the prototypes). The boundary is
per-wallet state in Phase 1.

## Evaluation semantics

Pure function of three inputs:

```
evaluate(class, approvalWeight, secondsSinceThreshold)
    -> Authorized
     | NeedsApprovals { missing_weight }
     | TimelockActive { remaining_seconds }
```

- Approval weight below the class threshold → `NeedsApprovals`.
- Weight satisfied but a class timelock has not elapsed → `TimelockActive`.
- Otherwise → `Authorized`.

Because evaluation is deterministic and dependency-free, client-side previews
(SDK/dashboard), the Rust core, and contract enforcement all compute identical
results. A cross-implementation conformance test suite is a Phase 1 deliverable.

## Request lifecycle

```
requested ──► pending ──► approved ──► executed
                 │  ▲          │
        reject / │  └ approval │
        cancel   ▼   withdrawn  ▼
             rejected/cancelled/expired
```

- Requests carry an expiry timestamp; expired requests cannot be approved.
- Execution records the on-chain transaction hash, closing the loop between
  authorization record and chain state.
- **Prototype boundary:** requests are local authorization records. No
  signatures are produced and nothing is broadcast until a `Signer` +
  `ChainAdapter` implementation exists.

## Replay protection (design)

1. Every request carries a unique id and expiry.
2. Signing payloads include the domain string (`KEYMESH/tx-auth/v1`), the
   request id, the canonical encoding of the request fields, and the wallet's
   nonce counter — so a captured signature authorizes exactly one request on
   one wallet.
3. Contract-side enforcement will additionally track consumed request ids to
   make on-chain replay impossible even with re-orgs or retried transactions.

Items 2–3 are enforced in Phase 1 alongside real signing; the request model
already carries the required fields (ids, nonces, expiries).
