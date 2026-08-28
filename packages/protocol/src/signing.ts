/**
 * TSS/MPC signing abstraction — Phase 2.1 design only.
 *
 * Maturity: DESIGNED, NOT IMPLEMENTED, NOT AUDITED.
 * This module defines TYPE-ONLY abstractions for the future threshold signing
 * layer. It contains NO cryptographic implementation, NO private key handling,
 * and NO fake MPC. See docs/architecture/tss-mpc-architecture.md and
 * docs/protocol/tss-signing-protocol.md for the full design.
 */

import { ValidationError, bytesToHex, hexToBytes } from '@keymesh/types';
import { keccak_256 } from '@noble/hashes/sha3';
import type { KeymeshTransaction } from './canonical';

// ---------------------------------------------------------------------------
// Branded types
// ---------------------------------------------------------------------------

export type ParticipantId = string & { readonly __brand: 'ParticipantId' };
export type SigningProtocolVersion = string & { readonly __brand: 'SigningProtocolVersion' };
export type SessionId = `0x${string}` & { readonly __brand: 'SessionId' };

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Expected protocol version for MVP (placeholder, library-defined in Phase 2.2). */
export const SIGNING_PROTOCOL_V1 = 'cggmp21/v1' as SigningProtocolVersion;

/** Session ID is keccak256(...)=32 bytes → 66-char hex. */
const SESSION_ID_RE = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

// ---------------------------------------------------------------------------
// Participant identity
// ---------------------------------------------------------------------------

/**
 * Creates a ParticipantId from an identity fingerprint hex.
 * No key material is handled here — identity keys are out of scope for Phase 2.1.
 */
export function makeParticipantId(fingerprint: string): ParticipantId {
  if (!/^0x[0-9a-fA-F]{40,64}$/.test(fingerprint)) {
    throw new ValidationError(
      'ParticipantId must be 0x-prefixed hex (20-32 bytes)',
      'ParticipantId'
    );
  }
  return fingerprint.toLowerCase() as ParticipantId;
}

export function isValidParticipantId(value: string): boolean {
  return /^0x[0-9a-fA-F]{40,64}$/.test(value);
}

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

export function isValidSigningProtocolVersion(value: string): boolean {
  // Allow "name/variant" form; must be non-empty, printable, no whitespace.
  return /^[a-z0-9._-]+\/[a-z0-9._-]+$/i.test(value) && value.length <= 64;
}

// ---------------------------------------------------------------------------
// Session binding
// ---------------------------------------------------------------------------

export interface SessionBinding {
  wallet: `0x${string}`;
  chainId: bigint;
  nonce: bigint;
  digest: `0x${string}`;
  policyVersion: bigint;
  signingProtocolVersion: SigningProtocolVersion;
  random: `0x${string}`; // 32 bytes
}

function writeUint256BE(target: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 32; i++) {
    target[offset + 31 - i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
}

/**
 * Derives a SessionId deterministically from the session binding per
 * docs/protocol/tss-signing-protocol.md §2.1.
 *
 * This is a DOMAIN-ONLY helper (keccak over public fields + random). It does
 * NOT perform signing and does NOT handle private shares.
 */
export function deriveSessionId(binding: SessionBinding): SessionId {
  if (!ADDRESS_RE.test(binding.wallet)) {
    throw new ValidationError('invalid wallet address', 'wallet');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(binding.digest)) {
    throw new ValidationError('digest must be 32-byte hex', 'digest');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(binding.random)) {
    throw new ValidationError('random must be 32-byte hex', 'random');
  }
  if (!isValidSigningProtocolVersion(binding.signingProtocolVersion)) {
    throw new ValidationError('invalid signingProtocolVersion', 'signingProtocolVersion');
  }

  const versionBytes = new TextEncoder().encode(binding.signingProtocolVersion);
  // Layout: wallet(20) | chainId(32) | nonce(32) | digest(32) | policyVersion(32) | versionBytes | random(32)
  // For simplicity, hash sequentially (matches spec's abi.encodePacked intent).
  const walletBytes = hexToBytes(binding.wallet);
  const digestBytes = hexToBytes(binding.digest);
  const randomBytes = hexToBytes(binding.random);

  const out: number[] = [];
  const push = (b: Uint8Array) => {
    for (const x of b) out.push(x);
  };
  push(walletBytes);
  const chainBuf = new Uint8Array(32);
  writeUint256BE(chainBuf, 0, binding.chainId);
  push(chainBuf);
  const nonceBuf = new Uint8Array(32);
  writeUint256BE(nonceBuf, 0, binding.nonce);
  push(nonceBuf);
  push(digestBytes);
  const policyBuf = new Uint8Array(32);
  writeUint256BE(policyBuf, 0, binding.policyVersion);
  push(policyBuf);
  push(versionBytes);
  push(randomBytes);

  const preimage = new Uint8Array(out);
  return bytesToHex(keccak_256(preimage)) as SessionId;
}

export function isValidSessionId(value: string): boolean {
  return SESSION_ID_RE.test(value);
}

// ---------------------------------------------------------------------------
// Signing session state machine (type-only, no crypto)
// ---------------------------------------------------------------------------

export type SigningSessionStatus = 'Started' | 'Aborted' | 'Failed' | 'Completed';

export interface SigningSession {
  readonly sessionId: SessionId;
  readonly wallet: `0x${string}`;
  readonly digest: `0x${string}`;
  readonly nonce: bigint;
  readonly policyVersion: bigint;
  readonly signingProtocolVersion: SigningProtocolVersion;
  readonly participants: ParticipantId[];
  readonly threshold: number;
  status: SigningSessionStatus;
}

export function createSigningSession(params: {
  wallet: `0x${string}`;
  digest: `0x${string}`;
  nonce: bigint;
  policyVersion: bigint;
  signingProtocolVersion: SigningProtocolVersion;
  participants: ParticipantId[];
  threshold: number;
  random: `0x${string}`;
  chainId: bigint;
}): SigningSession {
  if (params.participants.length === 0) {
    throw new ValidationError('participants must be non-empty', 'participants');
  }
  if (params.threshold < 1 || params.threshold > params.participants.length) {
    throw new ValidationError('threshold out of range', 'threshold');
  }
  const sessionId = deriveSessionId({
    wallet: params.wallet,
    chainId: params.chainId,
    nonce: params.nonce,
    digest: params.digest,
    policyVersion: params.policyVersion,
    signingProtocolVersion: params.signingProtocolVersion,
    random: params.random,
  });
  return {
    sessionId,
    wallet: params.wallet,
    digest: params.digest,
    nonce: params.nonce,
    policyVersion: params.policyVersion,
    signingProtocolVersion: params.signingProtocolVersion,
    participants: [...params.participants],
    threshold: params.threshold,
    status: 'Started',
  };
}

/**
 * Monotonic transitions: Started → {Aborted, Failed, Completed}; terminal states reject all.
 * This mirrors TSS-INV-10.
 */
export function transitionSigningSession(
  session: SigningSession,
  to: SigningSessionStatus
): SigningSession {
  if (session.status !== 'Started') {
    throw new ValidationError(`cannot transition from terminal status ${session.status}`, 'status');
  }
  if (to === 'Started') {
    throw new ValidationError('cannot transition back to Started', 'status');
  }
  return { ...session, status: to };
}

// ---------------------------------------------------------------------------
// Future SigningProvider interface (type-only)
// ---------------------------------------------------------------------------

/**
 * Conceptual interface for the future signing layer.
 * No implementation exists in Phase 2.1. See docs/architecture/tss-mpc-architecture.md §27.
 */
export interface SigningProvider {
  readonly kind: 'single' | 'threshold';
  readonly protocolVersion: SigningProtocolVersion;
}

// Re-export canonical type for convenience.
export type { KeymeshTransaction };
