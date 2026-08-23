import {
  type Policy,
  type PolicyRule,
  type TransactionType,
  createPolicy,
  getThreshold,
  isHighValue,
  updateRule,
} from '@keymesh/protocol';
import { NotFoundError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface UpsertPolicyRuleInput {
  type: TransactionType;
  threshold: number;
  timelockHours?: number;
  valueThresholdWei?: string;
}

/**
 * Policies are evaluated locally in the prototype. The PolicyManager contract
 * becomes the enforcement point in Phase 1; the evaluation helpers are shared
 * so client-side preview and on-chain enforcement cannot drift.
 */
export class PolicyApi {
  private readonly policies = new Map<string, Policy>();

  constructor(private readonly storage: WalletStorage) {}

  async ensureForWallet(walletId: string): Promise<Policy> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);

    const existing = this.policies.get(wallet.policyId);
    if (existing) return existing;

    const policy = createPolicy({
      id: wallet.policyId,
      walletId,
      name: 'Default policy',
    });
    this.policies.set(policy.id, policy);
    return policy;
  }

  async get(walletId: string): Promise<Policy> {
    return this.ensureForWallet(walletId);
  }

  async upsertRule(walletId: string, input: UpsertPolicyRuleInput): Promise<Policy> {
    const policy = await this.get(walletId);
    const rule: PolicyRule = {
      type: input.type,
      threshold: input.threshold,
      timelockHours: input.timelockHours,
      valueThresholdWei: input.valueThresholdWei,
    };
    const updated = updateRule(policy, rule);
    this.policies.set(updated.id, updated);
    return updated;
  }

  /** Preview-only evaluation. On-chain enforcement is authoritative once shipped. */
  async requiredApprovals(walletId: string, type: TransactionType): Promise<number> {
    return getThreshold(await this.get(walletId), type);
  }

  async classifiesAsHighValue(walletId: string, valueWei: bigint): Promise<boolean> {
    return isHighValue(await this.get(walletId), valueWei);
  }
}
