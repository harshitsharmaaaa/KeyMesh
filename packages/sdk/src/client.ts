import type { TransactionRequest, Wallet } from '@keymesh/protocol';

/**
 * Configuration for the KeyMesh client.
 *
 * SECURITY NOTE: This foundation release operates entirely on local state.
 * No private keys are handled by the client itself; signing is delegated to
 * a pluggable `Signer` implementation supplied by the integrator.
 */
export interface KeymeshClientConfig {
  /** EVM chain id the client operates on. */
  chainId: number;
  /** Storage backend for wallet state (in-memory by default). */
  storage?: WalletStorage;
}

/**
 * Persistence boundary for wallet state.
 *
 * The production implementation will persist protocol state off-chain /
 * on-chain. The in-memory implementation exists only for development.
 */
export interface WalletStorage {
  get(walletId: string): Promise<Wallet | null>;
  set(wallet: Wallet): Promise<void>;
  delete(walletId: string): Promise<void>;
  list(): Promise<Wallet[]>;
}

/**
 * Signing abstraction.
 *
 * PROTOTYPE BOUNDARY: no real cryptographic backend ships in this release.
 * Integrators must supply a signer backed by a reviewed library (e.g. an
 * audited secp256k1 implementation) or a hardware wallet / TSS service.
 * Never implement signing primitives yourself.
 */
export interface Signer {
  getAddress(): Promise<string>;
  signMessage(message: Uint8Array): Promise<Uint8Array>;
  signTransaction(request: TransactionRequest): Promise<Uint8Array>;
}

/** Minimal chain adapter surface so a future Solana adapter can slot in. */
export interface ChainAdapter {
  readonly chainKind: 'evm' | 'solana';
  getChainId(): Promise<number>;
  submitTransaction(signedTx: Uint8Array): Promise<string>;
}

export class InMemoryWalletStorage implements WalletStorage {
  private wallets = new Map<string, Wallet>();

  async get(walletId: string): Promise<Wallet | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async set(wallet: Wallet): Promise<void> {
    this.wallets.set(wallet.id, wallet);
  }

  async delete(walletId: string): Promise<void> {
    this.wallets.delete(walletId);
  }

  async list(): Promise<Wallet[]> {
    return [...this.wallets.values()];
  }
}

export function createInMemoryStorage(): WalletStorage {
  return new InMemoryWalletStorage();
}
