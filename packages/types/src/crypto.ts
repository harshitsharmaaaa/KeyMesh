export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface Signature {
  r: Uint8Array;
  s: Uint8Array;
  v: number;
}

export interface SignedMessage {
  message: Uint8Array;
  signature: Signature;
}

export type CurveType = 'secp256k1' | 'ed25519';

export interface CryptoProvider {
  generateKeyPair(curve: CurveType): Promise<KeyPair>;
  sign(message: Uint8Array, privateKey: Uint8Array, curve: CurveType): Promise<Signature>;
  verify(
    message: Uint8Array,
    signature: Signature,
    publicKey: Uint8Array,
    curve: CurveType
  ): Promise<boolean>;
  getPublicKey(privateKey: Uint8Array, curve: CurveType): Promise<Uint8Array>;
}

export const SUPPORTED_CURVES: CurveType[] = ['secp256k1', 'ed25519'];

export function isValidCurve(curve: string): curve is CurveType {
  return SUPPORTED_CURVES.includes(curve as CurveType);
}
