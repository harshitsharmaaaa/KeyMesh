import { z } from 'zod';
import type { GuardianType } from './constants';

export const GuardianSchema = z.object({
  id: z.string().uuid(),
  walletId: z.string().uuid(),
  type: z.enum(['eoa', 'contract', 'hardware', 'social']),
  address: z
    .string()
    .regex(/^0x[0-9a-fA-F]{40}$/)
    .optional(),
  publicKey: z
    .string()
    .regex(/^0x[0-9a-fA-F]+$/)
    .optional(),
  name: z.string().min(1).max(100),
  weight: z.number().int().positive().default(1),
  addedAt: z.number().int().positive(),
  removedAt: z.number().int().positive().nullable(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Guardian = z.infer<typeof GuardianSchema>;

/**
 * PROTOTYPE NOTE: guardian records here carry identity metadata only.
 * No key shares, signatures, or custody of any kind are represented.
 */
export interface CreateGuardianParams {
  id: string;
  walletId: string;
  type: GuardianType;
  name: string;
  address?: `0x${string}`;
  publicKey?: `0x${string}`;
  weight?: number;
  metadata?: Record<string, unknown>;
}

export function createGuardian(params: CreateGuardianParams): Guardian {
  return {
    id: params.id,
    walletId: params.walletId,
    type: params.type,
    address: params.address,
    publicKey: params.publicKey,
    name: params.name,
    weight: params.weight ?? 1,
    addedAt: Date.now(),
    removedAt: null,
    metadata: params.metadata ?? {},
  };
}

export function removeGuardianRecord(guardian: Guardian): Guardian {
  return { ...guardian, removedAt: Date.now() };
}

export function isActive(guardian: Guardian): boolean {
  return guardian.removedAt === null;
}

export function getGuardianWeight(guardian: Guardian): number {
  return isActive(guardian) ? guardian.weight : 0;
}

/** Weighted threshold check over a guardian set. */
export function totalActiveWeight(guardians: Guardian[]): number {
  return guardians.filter(isActive).reduce((sum, g) => sum + g.weight, 0);
}

export function meetsThreshold(guardians: Guardian[], threshold: number): boolean {
  return totalActiveWeight(guardians) >= threshold;
}
