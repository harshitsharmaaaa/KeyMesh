import {
  AUTHORIZATION_MODES,
  type AuthorizationMode,
  type ClassificationInput,
  POLICY_CONFIG_EXAMPLE,
  type PolicyConfig,
  classifyTransaction,
  effectiveRequestQuorum,
} from '@keymesh/protocol';
import { NotFoundError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface UpdatePolicyConfigInput {
  defaultMode?: AuthorizationMode;
  /** Wei as a decimal string (JSON-safe uint256). */
  valueThresholdWei?: string;
  guardianApprovalsRequired?: number;
}

/**
 * Local prototype policy store. The PolicyManager CONTRACT is the
 * authoritative enforcement point (Phase 1.3); this API mirrors its
 * configuration model and reuses the shared classification helper so a
 * client-side preview cannot drift from on-chain semantics.
 */
export class PolicyApi {
  private readonly policies = new Map<string, PolicyConfig>();

  constructor(private readonly storage: WalletStorage) {}

  async ensureForWallet(walletId: string): Promise<PolicyConfig> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);

    const existing = this.policies.get(walletId);
    if (existing) return existing;

    // Prototype default mirrors docs/protocol/policies.md suggestions:
    // device-only default, 1 ETH threshold, two guardian approvals.
    const policy: PolicyConfig = { ...POLICY_CONFIG_EXAMPLE };
    this.policies.set(walletId, policy);
    return policy;
  }

  async get(walletId: string): Promise<PolicyConfig> {
    return this.ensureForWallet(walletId);
  }

  async update(walletId: string, input: UpdatePolicyConfigInput): Promise<PolicyConfig> {
    const current = await this.get(walletId);
    const updated: PolicyConfig = {
      defaultMode: input.defaultMode ?? current.defaultMode,
      valueThresholdWei: input.valueThresholdWei ?? current.valueThresholdWei,
      guardianApprovalsRequired:
        input.guardianApprovalsRequired ?? current.guardianApprovalsRequired,
      version: current.version + 1, // any change bumps the version
    };
    this.policies.set(walletId, updated);
    return updated;
  }

  /** Preview-only classification. On-chain evaluation is authoritative. */
  async classify(walletId: string, tx: ClassificationInput): Promise<AuthorizationMode> {
    const config = await this.get(walletId);
    return classifyTransaction(
      config,
      {
        toIsPolicyManagerWithAdminSelector: false, // local preview has no contract address
        selectorRestricted: false,
        destinationRestricted: false,
      },
      tx
    );
  }

  /**
   * Guardian approvals required for `tx` under the local policy preview;
   * zero when the classification is device-only.
   */
  async requiredGuardianApprovals(walletId: string, tx: ClassificationInput): Promise<number> {
    const mode = await this.classify(walletId, tx);
    if (mode === AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS) {
      return effectiveRequestQuorum(await this.get(walletId));
    }
    return 0;
  }
}
