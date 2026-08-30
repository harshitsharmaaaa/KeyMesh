/**
 * TSS lifecycle SDK — Phase 2.6
 * Dedicated session for threshold key lifecycle (refresh, rotation, retirement).
 * Never exposes secret shares, Paillier secrets, or private scalars.
 */

import type {
  ParticipantSet,
  TssKeyMetadata,
  TssKeyState,
  TssRotationRequest,
  TssRotationStatus,
} from '@keymesh/protocol';

export type TssLifecycleEvent =
  | 'KeyCreated'
  | 'Refreshed'
  | 'RotationInitiated'
  | 'RotationApproved'
  | 'RotationCompleted'
  | 'Retired';

export interface TssLifecycleApi {
  getParticipantSet(): Promise<ParticipantSet>;
  getKeyId(): Promise<`0x${string}`>;
  getKeyMetadata(): Promise<TssKeyMetadata>;
  getKeyState(): Promise<TssKeyState>;
  refresh(): Promise<{ before: `0x${string}`; after: `0x${string}` }>;
  getRotationStatus(id: number): Promise<TssRotationRequest>;
  initiateRotation(input: InitiateRotationInput): Promise<TssRotationRequest>;
  approveRotation(id: number, guardian: string): Promise<TssRotationRequest>;
  cancelRotation(id: number): Promise<TssRotationRequest>;
  finalizeRotation(id: number): Promise<TssRotationRequest>;
  retire(): Promise<void>;
}

export type InitiateRotationInput = {
  wallet: `0x${string}`;
  oldParticipantSetVersion: number;
  newParticipantSet: `0x${string}`[];
  threshold: number;
  requestedBy: string;
  governanceReference: string;
  groupPublicKey: `0x${string}`;
};

// In-memory prototype implementation (local state, no crypto)
export class InMemoryTssLifecycle implements TssLifecycleApi {
  private metadata: TssKeyMetadata;
  private rotationRequests = new Map<number, TssRotationRequest>();
  private nextId = 1;

  constructor(initial: TssKeyMetadata) {
    this.metadata = { ...initial };
  }

  async getParticipantSet(): Promise<ParticipantSet> {
    return {
      // biome-ignore lint/suspicious/noExplicitAny: placeholder — real SDK would fetch from keymesh-tss service
      participants: [] as any,
      threshold: this.metadata.threshold,
      total: this.metadata.total,
      version: this.metadata.participantSetVersion,
    };
  }

  async getKeyId(): Promise<`0x${string}`> {
    return this.metadata.keyId as `0x${string}`;
  }

  async getKeyMetadata(): Promise<TssKeyMetadata> {
    return { ...this.metadata };
  }

  async getKeyState(): Promise<TssKeyState> {
    return this.metadata.state;
  }

  async refresh(): Promise<{ before: `0x${string}`; after: `0x${string}` }> {
    if (this.metadata.state !== 'Active')
      throw new Error(`refresh only from Active, got ${this.metadata.state}`);
    const before = this.metadata.keyId as `0x${string}`;
    // Refresh preserves group key and version (same participant set)
    // In real impl this would call Rust KeyLifecycle::refresh() via WASM/FFI and verify preserved VK
    this.metadata.state = 'Active';
    return { before, after: this.metadata.keyId as `0x${string}` };
  }

  async getRotationStatus(id: number): Promise<TssRotationRequest> {
    const r = this.rotationRequests.get(id);
    if (!r) throw new Error(`rotation ${id} not found`);
    return { ...r };
  }

  async initiateRotation(input: InitiateRotationInput): Promise<TssRotationRequest> {
    if (this.metadata.state !== 'Active')
      throw new Error(`rotation only from Active, got ${this.metadata.state}`);
    if (input.oldParticipantSetVersion !== this.metadata.participantSetVersion)
      throw new Error(
        `stale version: expected ${this.metadata.participantSetVersion}, got ${input.oldParticipantSetVersion}`
      );
    const id = this.nextId++;
    const req: TssRotationRequest = {
      id,
      // biome-ignore lint/suspicious/noExplicitAny: wallet branded string
      wallet: input.wallet as any,
      oldParticipantSetVersion: input.oldParticipantSetVersion,
      // biome-ignore lint/suspicious/noExplicitAny: participant ids branded
      newParticipantSet: input.newParticipantSet as any,
      threshold: input.threshold,
      requestedBy: input.requestedBy,
      governanceReference: input.governanceReference,
      createdAt: Math.floor(Date.now() / 1000),
      executableAt: null,
      status: 'Pending',
      approvals: [],
      quorumRequired: 2,
      timelockSeconds: 3600,
      // biome-ignore lint/suspicious/noExplicitAny: compressed key branded
      groupPublicKey: input.groupPublicKey as any,
    };
    this.rotationRequests.set(id, req);
    // Governance: requires 2 guardians, timelock 3600
    return { ...req };
  }

  async approveRotation(id: number, guardian: string): Promise<TssRotationRequest> {
    const r = this.rotationRequests.get(id);
    if (!r) throw new Error(`rotation ${id} not found`);
    if (r.status !== 'Pending') throw new Error(`can only approve Pending, got ${r.status}`);
    if (r.approvals.includes(guardian)) throw new Error(`duplicate approval ${guardian}`);
    r.approvals.push(guardian);
    if (r.approvals.length >= r.quorumRequired) {
      r.status = 'QuorumReached';
      r.executableAt = Math.floor(Date.now() / 1000) + r.timelockSeconds;
    }
    return { ...r };
  }

  async cancelRotation(id: number): Promise<TssRotationRequest> {
    const r = this.rotationRequests.get(id);
    if (!r) throw new Error(`rotation ${id} not found`);
    if (['Completed', 'Cancelled', 'Failed'].includes(r.status))
      throw new Error(`terminal ${r.status}`);
    r.status = 'Cancelled';
    return { ...r };
  }

  async finalizeRotation(id: number): Promise<TssRotationRequest> {
    const r = this.rotationRequests.get(id);
    if (!r) throw new Error(`rotation ${id} not found`);
    // Check timelock elapsed (simulate)
    if (r.executableAt && Math.floor(Date.now() / 1000) < r.executableAt)
      throw new Error('timelock not elapsed');
    if (r.status !== 'QuorumReached' && r.status !== 'Executable')
      throw new Error(`not executable: ${r.status}`);
    // In real impl: call Rust KeyLifecycle::rotate_with_request which does KeyResharing
    r.status = 'Resharing' as TssRotationStatus;
    // Simulate success
    r.status = 'Completed';
    this.metadata.participantSetVersion += 1;
    // keyId changes because version part of hash — real derive would hash new version
    this.metadata.state = 'Active';
    return { ...r };
  }

  async retire(): Promise<void> {
    if (this.metadata.state === 'Retired') throw new Error('already retired');
    this.metadata.state = 'Retired';
  }
}
