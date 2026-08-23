/**
 * @keymesh/sdk — public entry point.
 *
 * MATURITY: prototype. All state is local; no network calls, no signatures,
 * no key material handling. See docs/security/security-model.md for the
 * precise list of guarantees this build does and does not provide.
 */
export { GuardianApi, type CreateGuardianInput } from './guardian';
export { PolicyApi, type UpsertPolicyRuleInput } from './policy';
export { RecoveryApi, type StartRecoveryInput } from './recovery';
export { TransactionApi, type RequestTransactionInput } from './transaction';
export {
  type ChainAdapter,
  InMemoryWalletStorage,
  type KeymeshClientConfig,
  type Signer,
  type WalletStorage,
  createInMemoryStorage,
} from './client';
export { WalletApi, type CreateDeviceInput, type CreateWalletInput } from './wallet';

import type {
  Device,
  Guardian,
  GuardianType,
  Policy,
  Recovery,
  RecoveryState,
  TransactionRequest,
  TransactionType,
  Wallet,
} from '@keymesh/protocol';
import { type KeymeshClientConfig, type WalletStorage, createInMemoryStorage } from './client';
import { GuardianApi } from './guardian';
import { PolicyApi } from './policy';
import { RecoveryApi } from './recovery';
import { TransactionApi } from './transaction';
import { WalletApi } from './wallet';

/** Re-exported domain types so consumers only need the SDK surface. */
export type {
  Wallet,
  Device,
  Guardian,
  Recovery,
  Policy,
  TransactionRequest,
  GuardianType,
  RecoveryState,
  TransactionType,
};

/**
 * Facade over the protocol domain APIs. The dashboard depends only on this
 * surface — it must never import `@keymesh/protocol` internals directly.
 */
export class KeymeshClient {
  readonly chainId: number;
  readonly wallets: WalletApi;
  readonly guardians: GuardianApi;
  readonly recovery: RecoveryApi;
  readonly transactions: TransactionApi;
  readonly policies: PolicyApi;

  constructor(config: KeymeshClientConfig, storage: WalletStorage = createInMemoryStorage()) {
    this.chainId = config.chainId;
    this.wallets = new WalletApi(storage);
    this.guardians = new GuardianApi(storage);
    this.recovery = new RecoveryApi(storage);
    this.transactions = new TransactionApi(storage);
    this.policies = new PolicyApi(storage);
  }

  /** Convenience passthroughs matching the documented example flow. */
  createKeymeshWallet(input: Parameters<WalletApi['create']>[0]): Promise<Wallet> {
    return this.wallets.create(input);
  }

  addGuardian(walletId: string, input: Parameters<GuardianApi['add']>[1]): Promise<Guardian> {
    return this.guardians.add(walletId, input);
  }

  requestTransaction(
    walletId: string,
    input: Parameters<TransactionApi['request']>[1]
  ): Promise<TransactionRequest> {
    return this.transactions.request(walletId, input);
  }

  startRecovery(walletId: string, input: Parameters<RecoveryApi['start']>[1]): Promise<Recovery> {
    return this.recovery.start(walletId, input);
  }

  getPolicy(walletId: string): Promise<Policy> {
    return this.policies.get(walletId);
  }
}

export function createKeymeshClient(
  config: KeymeshClientConfig,
  storage?: WalletStorage
): KeymeshClient {
  return new KeymeshClient(config, storage);
}
