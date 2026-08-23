import {
  type TransactionType,
  approveTransaction,
  cancelTransaction,
  createTransactionRequest,
} from '@keymesh/protocol';
import { NotFoundError, ProtocolError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface RequestTransactionInput {
  type: TransactionType;
  to: `0x${string}`;
  value: bigint;
  data?: `0x${string}`;
  requestedByDeviceId: string;
  requiredApprovals: number;
  expiresInSeconds?: number;
}

/**
 * PROTOTYPE: transaction requests are tracked locally and never broadcast.
 * Submission requires a Signer + ChainAdapter; both are explicit TODO
 * boundaries for Phase 1. No signature is produced anywhere in this release.
 */
export class TransactionApi {
  private readonly requests = new Map<string, ReturnType<typeof createTransactionRequest>>();

  constructor(private readonly storage: WalletStorage) {}

  async request(walletId: string, input: RequestTransactionInput) {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);

    const device = wallet.devices.find((d) => d.id === input.requestedByDeviceId);
    if (!device || device.revokedAt !== null) {
      throw new ProtocolError('Transactions must be requested by an active device');
    }

    const request = createTransactionRequest({
      id: crypto.randomUUID(),
      walletId,
      type: input.type,
      from: wallet.address as `0x${string}`,
      to: input.to,
      value: input.value,
      data: input.data ?? '0x',
      chainId: wallet.chainId,
      requestedBy: input.requestedByDeviceId,
      requiredApprovals: input.requiredApprovals,
      expiresAt: input.expiresInSeconds ? Date.now() + input.expiresInSeconds * 1000 : undefined,
    });
    this.requests.set(request.id, request);
    return request;
  }

  async get(requestId: string) {
    const request = this.requests.get(requestId);
    if (!request) throw new NotFoundError('TransactionRequest', requestId);
    return request;
  }

  async listByWallet(walletId: string) {
    return [...this.requests.values()].filter((r) => r.walletId === walletId);
  }

  async approve(requestId: string, approverDeviceId: string) {
    const request = await this.get(requestId);
    const updated = approveTransaction(request, approverDeviceId);
    this.requests.set(updated.id, updated);
    return updated;
  }

  async cancel(requestId: string) {
    const updated = cancelTransaction(await this.get(requestId));
    this.requests.set(updated.id, updated);
    return updated;
  }
}
