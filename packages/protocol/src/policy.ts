import { z } from 'zod';

/**
 * Shared transaction-authorization policy domain types for Phase 1.3.
 *
 * These mirror the on-chain `IPolicyManager` surface one-for-one (same mode
 * names, same status order) so off-chain previews can be checked against
 * on-chain decisions. Classification precedence lives in
 * `classifyTransaction` here, in Rust (`keymesh-core/src/policy`) and in
 * Solidity — the three must stay in sync (see docs/protocol/policies.md).
 */

/** Mirrors IPolicyManager.AuthorizationMode discriminants 0..1. */
export const AUTHORIZATION_MODES = {
  DEVICE_ONLY: 'device_only',
  DEVICE_PLUS_GUARDIANS: 'device_plus_guardians',
} as const;

export type AuthorizationMode = (typeof AUTHORIZATION_MODES)[keyof typeof AUTHORIZATION_MODES];

export const AUTHORIZATION_MODE_DISCRIMINANTS = {
  device_only: 0,
  device_plus_guardians: 1,
} as const satisfies Record<AuthorizationMode, number>;

/** Mirrors IPolicyManager.TxnAuthStatus discriminants 0..4. */
export const TXN_AUTHORIZATION_STATUSES = {
  NONE: 'none',
  PENDING: 'pending',
  AUTHORIZED: 'authorized',
  EXECUTED: 'executed',
  CANCELLED: 'cancelled',
} as const;

export type TransactionAuthorizationStatus =
  (typeof TXN_AUTHORIZATION_STATUSES)[keyof typeof TXN_AUTHORIZATION_STATUSES];

export const TXN_AUTHORIZATION_STATUS_DISCRIMINANTS = {
  none: 0,
  pending: 1,
  authorized: 2,
  executed: 3,
  cancelled: 4,
} as const satisfies Record<TransactionAuthorizationStatus, number>;

const hexAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const hexBytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const decimalUint = z.string().regex(/^\d+$/);

/**
 * A wallet's policy configuration. `valueThresholdWei` uses a decimal string
 * because JSON cannot carry uint256 precisely; version 0 means unconfigured
 * (the wallet then behaves exactly like Phase 1.1).
 */
export const PolicyConfigSchema = z.object({
  defaultMode: z.enum([AUTHORIZATION_MODES.DEVICE_ONLY, AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS]),
  valueThresholdWei: decimalUint,
  guardianApprovalsRequired: z.number().int().min(0),
  version: z.number().int().min(0),
});

export type PolicyConfig = z.infer<typeof PolicyConfigSchema>;

/** A per-digest guardian transaction authorization. */
export const TransactionAuthorizationSchema = z.object({
  digest: hexBytes32,
  wallet: hexAddress,
  requester: hexAddress,
  requestedAt: z.number().int().nonnegative(),
  policyVersion: z.number().int().nonnegative(),
  approvals: z.number().int().nonnegative(),
  approvalsRequired: z.number().int().nonnegative(),
  status: z.enum([
    TXN_AUTHORIZATION_STATUSES.NONE,
    TXN_AUTHORIZATION_STATUSES.PENDING,
    TXN_AUTHORIZATION_STATUSES.AUTHORIZED,
    TXN_AUTHORIZATION_STATUSES.EXECUTED,
    TXN_AUTHORIZATION_STATUSES.CANCELLED,
  ]),
});

export type TransactionAuthorization = z.infer<typeof TransactionAuthorizationSchema>;

/** Inputs describing a hypothetical transaction for classification. */
export interface ClassificationInput {
  /** Recipient address. */
  to: `0x${string}`;
  /** Wei value as a decimal string (JSON-safe uint256). */
  valueWei: string;
  /** Calldata; only the first 4 bytes matter, when present. */
  data?: `0x${string}`;
}

function hasSelector(data: string | undefined): boolean {
  return typeof data === 'string' && data.length >= 10; // '0x' + 4 bytes
}

/**
 * Deterministic classification — precedence (first match wins):
 *   1. policy-administration selector -> DEVICE_PLUS_GUARDIANS (structural)
 *   2. restricted selector            -> DEVICE_PLUS_GUARDIANS
 *   3. restricted destination         -> DEVICE_PLUS_GUARDIANS
 *   4. value > threshold              -> DEVICE_PLUS_GUARDIANS
 *   5. otherwise                      -> wallet default mode
 *
 * Unconfigured wallets (version 0) are DEVICE_ONLY except rule 1.
 */
export function classifyTransaction(
  config: PolicyConfig,
  restrictions: {
    toIsPolicyManagerWithAdminSelector: boolean;
    selectorRestricted: boolean;
    destinationRestricted: boolean;
  },
  tx: ClassificationInput
): AuthorizationMode {
  if (restrictions.toIsPolicyManagerWithAdminSelector && hasSelector(tx.data)) {
    return AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS;
  }
  if (!config || config.version === 0) {
    return AUTHORIZATION_MODES.DEVICE_ONLY;
  }
  if (hasSelector(tx.data) && restrictions.selectorRestricted) {
    return AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS;
  }
  if (restrictions.destinationRestricted) {
    return AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS;
  }
  if (BigInt(tx.valueWei) > BigInt(config.valueThresholdWei)) {
    return AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS;
  }
  return config.defaultMode;
}

/** Effective quorum for NEW requests; never zero (bootstrap minimum is 1). */
export function effectiveRequestQuorum(config: PolicyConfig): number {
  return config.guardianApprovalsRequired === 0 ? 1 : config.guardianApprovalsRequired;
}

/** ANY policy change invalidates authorizations from older versions. */
export function isAuthorizationVersionValid(
  requestVersion: number,
  currentVersion: number
): boolean {
  return requestVersion === currentVersion;
}

/** Example fixtures for tests/docs; not real addresses in use anywhere. */
export const POLICY_CONFIG_EXAMPLE: PolicyConfig = {
  defaultMode: AUTHORIZATION_MODES.DEVICE_ONLY,
  valueThresholdWei: '1000000000000000000',
  guardianApprovalsRequired: 2,
  version: 1,
};
