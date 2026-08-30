/**
 * TSS Key Lifecycle, Refresh & Guardian-Governed Participant Rotation — Phase 2.6
 *
 * Key lifecycle state and governed rotation request types.
 * Cryptographic shares never exposed to TypeScript layer; only identities, group key, version, and governance metadata.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Participant set
// ---------------------------------------------------------------------------

export const TssParticipantIdSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40,64}$/, 'ParticipantId must be 0x hex 20-32 bytes');

export type TssParticipantId = z.infer<typeof TssParticipantIdSchema>;

export const ParticipantSetSchema = z.object({
  participants: z.array(TssParticipantIdSchema).min(1),
  threshold: z.number().int().min(1),
  total: z.number().int().min(1),
  version: z.number().int().min(1),
});

export type ParticipantSet = z.infer<typeof ParticipantSetSchema>;

export function validateParticipantSet(ps: ParticipantSet): void {
  if (ps.threshold > ps.participants.length) {
    throw new Error(`threshold ${ps.threshold} > participants ${ps.participants.length}`);
  }
  if (ps.total !== ps.participants.length) {
    throw new Error(`total ${ps.total} != participants length ${ps.participants.length}`);
  }
  const uniq = new Set(ps.participants);
  if (uniq.size !== ps.participants.length) throw new Error('duplicate participant');
}

// ---------------------------------------------------------------------------
// Key state
// ---------------------------------------------------------------------------

export const TssKeyStateSchema = z.enum(['Created', 'Active', 'Refreshing', 'Rotating', 'Retired']);
export type TssKeyState = z.infer<typeof TssKeyStateSchema>;

export const TssRefreshStatusSchema = z.enum(['None', 'InProgress', 'Completed', 'Failed']);
export type TssRefreshStatus = z.infer<typeof TssRefreshStatusSchema>;

// ---------------------------------------------------------------------------
// Key identifier / metadata
// ---------------------------------------------------------------------------

export const TssKeyMetadataSchema = z.object({
  keyId: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  groupPublicKey: z.string().regex(/^0x[0-9a-fA-F]{66}$/, 'compressed secp256k1 33 bytes'),
  ethereumAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  threshold: z.number().int().min(1),
  total: z.number().int().min(1),
  participantSetVersion: z.number().int().min(1),
  protocolVersion: z.string().min(1),
  state: TssKeyStateSchema,
});

export type TssKeyMetadata = z.infer<typeof TssKeyMetadataSchema>;

// ---------------------------------------------------------------------------
// Rotation request
// ---------------------------------------------------------------------------

export const TssRotationStatusSchema = z.enum([
  'None',
  'Pending',
  'QuorumReached',
  'Executable',
  'Resharing',
  'Completed',
  'Cancelled',
  'Failed',
]);
export type TssRotationStatus = z.infer<typeof TssRotationStatusSchema>;

export const TssRotationRequestSchema = z.object({
  id: z.number().int().min(0),
  wallet: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  oldParticipantSetVersion: z.number().int().min(1),
  newParticipantSet: z.array(TssParticipantIdSchema).min(1),
  threshold: z.number().int().min(1),
  requestedBy: z.string().min(1),
  governanceReference: z.string().min(1),
  createdAt: z.number().int().min(0),
  executableAt: z.number().int().min(0).nullable(),
  status: TssRotationStatusSchema,
  approvals: z.array(z.string().min(1)),
  quorumRequired: z.number().int().min(1),
  timelockSeconds: z.number().int().min(3600),
  groupPublicKey: z.string().regex(/^0x[0-9a-fA-F]{66}$/),
});

export type TssRotationRequest = z.infer<typeof TssRotationRequestSchema>;

// ---------------------------------------------------------------------------
// Helpers: participant-set identity hashing (deterministic, cross-language vectors)
// ---------------------------------------------------------------------------

import { keccak_256 } from '@noble/hashes/sha3';

export function deriveKeyId(
  groupPublicKeyCompressedHex: `0x${string}`,
  threshold: number,
  version: number,
  protocolVersion = 'synedrion/0.3-cggmp24'
): `0x${string}` {
  const pkBytes = hexToBytes(groupPublicKeyCompressedHex);
  const protoBytes = new TextEncoder().encode(protocolVersion);
  const thBuf = new Uint8Array(8);
  new DataView(thBuf.buffer).setBigUint64(0, BigInt(threshold), false);
  const verBuf = new Uint8Array(8);
  new DataView(verBuf.buffer).setBigUint64(0, BigInt(version), false);
  const preimage = new Uint8Array(pkBytes.length + protoBytes.length + 16);
  preimage.set(pkBytes, 0);
  preimage.set(protoBytes, pkBytes.length);
  preimage.set(thBuf, pkBytes.length + protoBytes.length);
  preimage.set(verBuf, pkBytes.length + protoBytes.length + 8);
  const hash = keccak_256(preimage);
  return `0x${bytesToHex(hash)}`;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Test vectors for cross-language checks (deterministic metadata)
export const TSS_LIFECYCLE_VECTORS = {
  keyId_v1: deriveKeyId('0x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 2, 1),
  keyId_v2: deriveKeyId('0x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 2, 2),
} as const;
