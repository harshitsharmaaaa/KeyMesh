/**
 * Future SigningProvider boundary — Phase 2.2 (prototype, not integrated).
 * Defines how Phase 2.3 will swap SingleEcdsaSigner → ThresholdEcdsaSigner
 * without touching PolicyManager / RecoveryManager / KEYMESH_TX_V1.
 */

import type { ParticipantId, SessionId, SigningProtocolVersion } from './signing';

export type ThresholdConfig = {
  total: number;
  threshold: number;
};

export type SessionContext = {
  wallet: `0x${string}`;
  chainId: bigint;
  nonce: bigint;
  digest: `0x${string}`;
  policyVersion: bigint;
  sessionId: SessionId;
  signingProtocolVersion: SigningProtocolVersion;
};

export interface SigningProvider {
  readonly kind: 'single' | 'threshold';
  readonly protocolVersion: SigningProtocolVersion;
  /**
   * Future: start a signing session bound to the given context.
   * In Phase 2.2 this is a type-only boundary; the Rust prototype
   * `crates/keymesh-tss-proto` proves the flow via `SessionBinding`.
   */
  startSession?(context: SessionContext): Promise<SessionId>;
  verifySignature?(
    digest: `0x${string}`,
    signature: { r: `0x${string}`; s: `0x${string}`; v: number }
  ): Promise<boolean>;
}

// Re-export for convenience
export type { ParticipantId, SessionId, SigningProtocolVersion };
