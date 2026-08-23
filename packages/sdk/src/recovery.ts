import {
  type Recovery,
  approveRecovery,
  cancelRecovery,
  completeRecovery,
  createRecovery,
} from '@keymesh/protocol';
import { NotFoundError, ProtocolError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface StartRecoveryInput {
  /** Device that initiated the recovery. */
  initiatorDeviceId: string;
  /** New device that will be authorized if recovery completes. */
  newDevicePublicKey: string;
  requiredApprovals: number;
  timelockHours?: number;
}

/**
 * Local recovery ledger for the prototype. Phase 1 moves this state onto the
 * RecoveryManager contract; transitions here mirror its intended state machine.
 */
export class RecoveryApi {
  private readonly recoveries = new Map<string, Recovery>();

  constructor(private readonly storage: WalletStorage) {}

  async start(walletId: string, input: StartRecoveryInput): Promise<Recovery> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);
    if (!wallet.devices.some((d) => d.id === input.initiatorDeviceId)) {
      throw new ProtocolError('Initiator device is not registered on this wallet');
    }
    if (input.requiredApprovals > wallet.guardians.length) {
      throw new ProtocolError(
        `requiredApprovals (${input.requiredApprovals}) exceeds active guardian count (${wallet.guardians.length})`
      );
    }

    const recovery = createRecovery({
      id: crypto.randomUUID(),
      walletId,
      initiatorId: input.initiatorDeviceId,
      newDeviceId: input.newDevicePublicKey,
      requiredApprovals: input.requiredApprovals,
      timelockHours: input.timelockHours ?? 168,
    });
    this.recoveries.set(recovery.id, recovery);
    return recovery;
  }

  async get(recoveryId: string): Promise<Recovery> {
    const recovery = this.recoveries.get(recoveryId);
    if (!recovery) throw new NotFoundError('Recovery', recoveryId);
    return recovery;
  }

  async listByWallet(walletId: string): Promise<Recovery[]> {
    return [...this.recoveries.values()].filter((r) => r.walletId === walletId);
  }

  async approve(recoveryId: string, guardianId: string): Promise<Recovery> {
    const recovery = await this.get(recoveryId);
    const updated = approveRecovery(recovery, guardianId);
    this.recoveries.set(updated.id, updated);
    return updated;
  }

  async complete(recoveryId: string): Promise<Recovery> {
    const recovery = await this.get(recoveryId);
    const updated = completeRecovery(recovery);
    if (updated.state !== 'completed') {
      throw new ProtocolError(
        `Recovery ${recoveryId} cannot be completed in state '${recovery.state}' (timelock may still be active)`
      );
    }
    this.recoveries.set(updated.id, updated);
    return updated;
  }

  async cancel(recoveryId: string): Promise<Recovery> {
    const recovery = await this.get(recoveryId);
    const updated = cancelRecovery(recovery);
    this.recoveries.set(updated.id, updated);
    return updated;
  }
}
