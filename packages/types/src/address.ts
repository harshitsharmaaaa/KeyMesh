export type HexString = `0x${string}`;

export interface Address {
  value: HexString;
}

export function isAddress(value: string): value is HexString {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function toAddress(value: string): Address {
  if (!isAddress(value)) {
    throw new Error(`Invalid Ethereum address: ${value}`);
  }
  return { value };
}

export function addressToString(address: Address): string {
  return address.value;
}
