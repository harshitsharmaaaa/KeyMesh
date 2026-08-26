# KeyMesh Security Findings

This file tracks issues discovered during Phase 1.4 security hardening.

## F-0001
- ID: `F-0001`
- Severity: `LOW`
- Description: The initial TypeScript fuzz test depended on `vitest/fast-check`, but the workspace did not include `fast-check`.
- Impact: The fuzz suite could not run in CI or locally.
- Reproduction: Run `bun test packages/protocol/src/canonical.fuzz.test.ts` before the fix.
- Fix: Replaced the dependency with deterministic Vitest coverage over the same boundary cases.
- Regression test: `packages/protocol/src/canonical.fuzz.test.ts`
- Status: `fixed`

## F-0002
- ID: `F-0002`
- Severity: `LOW`
- Description: One cross-language vector fixture used a malformed `to` address with the wrong hex length.
- Impact: The vector file was not trustworthy as a canonical reference set.
- Reproduction: Inspect `packages/protocol/src/gen_vectors.ts` before the fix.
- Fix: Corrected the address to a full 20-byte hex value.
- Regression test: `packages/protocol/src/canonical.test.ts`
- Status: `fixed`

## Summary
- No high-severity protocol findings have been confirmed during this pass.
- Remaining work is primarily test coverage hardening and CI integration.
