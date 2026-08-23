import { z } from 'zod';
import type { TransactionType } from './constants';

export const PolicyRuleSchema = z.object({
  type: z.enum(['normal', 'high_value', 'recovery', 'guardian_management', 'policy_update']),
  threshold: z.number().int().positive(),
  timelockHours: z.number().int().nonnegative().optional(),
  valueThresholdWei: z.string().regex(/^\d+$/).optional(),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  name: z.string().min(1).max(100),
  rules: z.array(PolicyRuleSchema),
  defaultThreshold: z.number().int().positive(),
  createdAt: z.number().int().positive(),
  updatedAt: z.number().int().positive(),
  version: z.number().int().positive(),
});

export type Policy = z.infer<typeof PolicySchema>;

/**
 * Default rules encode the conceptual model from docs/protocol/transaction-policy.md:
 *   normal             -> device only
 *   high_value         -> device + guardian quorum
 *   recovery           -> guardian threshold + timelock
 */
export const DEFAULT_RULES: PolicyRule[] = [
  { type: 'normal', threshold: 1 },
  { type: 'high_value', threshold: 2, valueThresholdWei: '1000000000000000000' },
  { type: 'recovery', threshold: 3, timelockHours: 168 },
  { type: 'guardian_management', threshold: 2, timelockHours: 24 },
  { type: 'policy_update', threshold: 2, timelockHours: 48 },
];

export interface CreatePolicyParams {
  id: string;
  walletId: string;
  name: string;
  rules?: PolicyRule[];
  defaultThreshold?: number;
}

export function createPolicy(params: CreatePolicyParams): Policy {
  const now = Date.now();
  return {
    id: params.id,
    walletId: params.walletId,
    name: params.name,
    rules: params.rules ?? DEFAULT_RULES,
    defaultThreshold: params.defaultThreshold ?? 1,
    createdAt: now,
    updatedAt: now,
    version: 1,
  };
}

export function getRule(policy: Policy, type: TransactionType): PolicyRule | undefined {
  return policy.rules.find((r) => r.type === type);
}

/** Effective approval threshold for a transaction class. */
export function getThreshold(policy: Policy, type: TransactionType): number {
  return getRule(policy, type)?.threshold ?? policy.defaultThreshold;
}

export function getTimelockHours(policy: Policy, type: TransactionType): number {
  return getRule(policy, type)?.timelockHours ?? 0;
}

export function getValueThreshold(policy: Policy, type: TransactionType): bigint | undefined {
  const wei = getRule(policy, type)?.valueThresholdWei;
  return wei === undefined ? undefined : BigInt(wei);
}

export function updateRule(policy: Policy, rule: PolicyRule): Policy {
  const exists = policy.rules.some((r) => r.type === rule.type);
  return {
    ...policy,
    rules: exists
      ? policy.rules.map((r) => (r.type === rule.type ? rule : r))
      : [...policy.rules, rule],
    updatedAt: Date.now(),
    version: policy.version + 1,
  };
}

export function removeRule(policy: Policy, type: TransactionType): Policy {
  return {
    ...policy,
    rules: policy.rules.filter((r) => r.type !== type),
    updatedAt: Date.now(),
    version: policy.version + 1,
  };
}

export function requiresTimelock(policy: Policy, type: TransactionType): boolean {
  return getTimelockHours(policy, type) > 0;
}

/** A value is "high value" when it meets or exceeds the configured threshold. */
export function isHighValue(policy: Policy, valueWei: bigint): boolean {
  const threshold = getValueThreshold(policy, 'high_value');
  return threshold !== undefined && valueWei >= threshold;
}
