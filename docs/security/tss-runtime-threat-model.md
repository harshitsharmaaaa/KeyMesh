# TSS Runtime Threat Model

## Scope

This document applies to the runtime boundary around the current real threshold-ECDSA prototype.

## Threats

| Threat | Impact | Mitigation |
|---|---|---|
| coordinator relays wrong messages | invalid signing or abort | session, digest, wallet, chain, participant, and version binding |
| participant restart | partial state loss | abort current signing session and start fresh |
| duplicate / reordered messages | session confusion | round validation and protocol checks |
| replay | cross-session misuse | fresh session IDs and envelope authentication |
| concurrent session cross-talk | incorrect binding | per-session state isolation |
| transport tampering | invalid input | authenticated envelopes |

## Security stance

The current transport is an authenticated TCP prototype, not production networking.

## What remains needed for a distributed runtime

- a supported external participant driver
- documented restart semantics
- documented concurrency semantics
- supported timeout and retry semantics
