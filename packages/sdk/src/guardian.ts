import { type Guardian, type GuardianType, addGuardian, removeGuardian } from '@keymesh/protocol';
import { NotFoundError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface CreateGuardianInput {
  type: GuardianType;
  name: string;
  /** On-chain address for EOA / contract guardians. */
  address?: `0x${string}`;
  publicKey?: string;
  weight?: number;
  metadata?: Record<string, unknown>;
}

/**
 * PROTOTYPE: guardians are stored as ids inside the local wallet state.
 * The on-chain GuardianRegistry contract is the source of truth once Phase 1
 * lands; this API will be re-pointed at it without changing call sites.
 */
export class GuardianApi {
  constructor(private readonly storage: WalletStorage) {}

  async add(walletId: string, input: CreateGuardianInput): Promise<Guardian> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);

    const guardian: Guardian = {
      id: crypto.randomUUID(),
      walletId,
      type: input.type,
      name: input.name,
      address: input.address,
      publicKey: input.publicKey as `0x${string}` | undefined,
      weight: input.weight ?? 1,
      addedAt: Date.now(),
      removedAt: null,
      metadata: input.metadata ?? {},
    };

    await this.storage.set(addGuardian(wallet, guardian.id));
    return guardian;
  }

  async remove(walletId: string, guardianId: string): Promise<void> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);
    if (!wallet.guardians.includes(guardianId)) {
      throw new NotFoundError('Guardian', guardianId);
    }
    await this.storage.set(removeGuardian(wallet, guardianId));
  }

  async listIds(walletId: string): Promise<string[]> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);
    return wallet.guardians;
  }
}
