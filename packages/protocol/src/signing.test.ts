import { describe, expect, it } from 'vitest';
import {
  SIGNING_PROTOCOL_V1,
  createSigningSession,
  deriveSessionId,
  isValidParticipantId,
  isValidSessionId,
  isValidSigningProtocolVersion,
  makeParticipantId,
  transitionSigningSession,
} from './signing';

const WALLET = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as const;
const DIGEST = '0xef48434b4ea47252caab3312aef0d299b5970bf1c8f1bd43e71c06791ad0b66a' as const;
const RANDOM = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const;
const RANDOM2 = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as const;

describe('signing abstraction — domain behavior only (Phase 2.1, no crypto)', () => {
  it('participant id validation', () => {
    expect(isValidParticipantId('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')).toBe(true);
    expect(
      isValidParticipantId('0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
    ).toBe(true);
    expect(isValidParticipantId('not-hex')).toBe(false);
    expect(() => makeParticipantId('bad')).toThrow();
    const id = makeParticipantId(WALLET);
    expect(id.toLowerCase()).toBe(id);
  });

  it('signing protocol version validation', () => {
    expect(isValidSigningProtocolVersion('cggmp21/v1')).toBe(true);
    expect(isValidSigningProtocolVersion('gg20/v2')).toBe(true);
    expect(isValidSigningProtocolVersion('')).toBe(false);
    expect(isValidSigningProtocolVersion('no-slash')).toBe(false);
    expect(SIGNING_PROTOCOL_V1).toBe('cggmp21/v1');
  });

  it('session id is deterministic and 32 bytes', () => {
    const a = deriveSessionId({
      wallet: WALLET,
      chainId: 31337n,
      nonce: 0n,
      digest: DIGEST,
      policyVersion: 1n,
      signingProtocolVersion: SIGNING_PROTOCOL_V1,
      random: RANDOM,
    });
    const b = deriveSessionId({
      wallet: WALLET,
      chainId: 31337n,
      nonce: 0n,
      digest: DIGEST,
      policyVersion: 1n,
      signingProtocolVersion: SIGNING_PROTOCOL_V1,
      random: RANDOM,
    });
    expect(a).toBe(b);
    expect(isValidSessionId(a)).toBe(true);
  });

  it('session id changes when any binding field changes', () => {
    const base = {
      wallet: WALLET,
      chainId: 31337n,
      nonce: 0n,
      digest: DIGEST,
      policyVersion: 1n,
      signingProtocolVersion: SIGNING_PROTOCOL_V1,
      random: RANDOM,
    } as const;
    const baseId = deriveSessionId(base);
    expect(deriveSessionId({ ...base, nonce: 1n })).not.toBe(baseId);
    expect(deriveSessionId({ ...base, chainId: 1n })).not.toBe(baseId);
    expect(deriveSessionId({ ...base, policyVersion: 2n })).not.toBe(baseId);
    expect(deriveSessionId({ ...base, random: RANDOM2 })).not.toBe(baseId);
    const otherDigest =
      '0x58f52cacdeacc22a70f0e855c44e50b34348984261d9c6954c48d6f895870b58' as const;
    expect(deriveSessionId({ ...base, digest: otherDigest })).not.toBe(baseId);
  });

  it('signing session lifecycle is monotonic (TSS-INV-10)', () => {
    const p1 = makeParticipantId('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const p2 = makeParticipantId('0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    const session = createSigningSession({
      wallet: WALLET,
      digest: DIGEST,
      nonce: 0n,
      policyVersion: 1n,
      signingProtocolVersion: SIGNING_PROTOCOL_V1,
      participants: [p1, p2],
      threshold: 2,
      random: RANDOM,
      chainId: 31337n,
    });
    expect(session.status).toBe('Started');

    const completed = transitionSigningSession(session, 'Completed');
    expect(completed.status).toBe('Completed');
    expect(() => transitionSigningSession(completed, 'Aborted')).toThrow();

    const aborted = transitionSigningSession(session, 'Aborted');
    expect(aborted.status).toBe('Aborted');
    expect(() => transitionSigningSession(aborted, 'Completed')).toThrow();
  });

  it('rejects invalid threshold', () => {
    const p1 = makeParticipantId('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(() =>
      createSigningSession({
        wallet: WALLET,
        digest: DIGEST,
        nonce: 0n,
        policyVersion: 1n,
        signingProtocolVersion: SIGNING_PROTOCOL_V1,
        participants: [p1],
        threshold: 2,
        random: RANDOM,
        chainId: 31337n,
      })
    ).toThrow();
  });

  it('rejects invalid binding fields', () => {
    expect(() =>
      deriveSessionId({
        wallet: '0xbad' as unknown as `0x${string}`,
        chainId: 1n,
        nonce: 0n,
        digest: DIGEST,
        policyVersion: 1n,
        signingProtocolVersion: SIGNING_PROTOCOL_V1,
        random: RANDOM,
      })
    ).toThrow();
  });
});
