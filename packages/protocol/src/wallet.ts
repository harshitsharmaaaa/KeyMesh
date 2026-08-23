import { z } from 'zod';

export const DeviceSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100),
  publicKey: z.string().regex(/^0x[0-9a-fA-F]+$/),
  curve: z.enum(['secp256k1', 'ed25519']),
  authorizedAt: z.number().int().positive(),
  revokedAt: z.number().int().positive().nullable(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Device = z.infer<typeof DeviceSchema>;

export const WalletSchema = z.object({
  id: z.string().uuid(),
  chainId: z.number().int().positive(),
  address: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  devices: z.array(DeviceSchema),
  guardians: z.array(z.string().uuid()),
  policyId: z.string().uuid(),
  createdAt: z.number().int().positive(),
  updatedAt: z.number().int().positive(),
  version: z.number().int().positive(),
});

export type Wallet = z.infer<typeof WalletSchema>;

export function createWallet(params: {
  id: string;
  chainId: number;
  address: { value: `0x${string}` };
  devices: Device[];
  guardians: string[];
  policyId: string;
}): Wallet {
  const now = Date.now();
  return {
    id: params.id,
    chainId: params.chainId,
    address: params.address.value,
    devices: params.devices,
    guardians: params.guardians,
    policyId: params.policyId,
    createdAt: now,
    updatedAt: now,
    version: 1,
  };
}

export function addDevice(wallet: Wallet, device: Device): Wallet {
  if (wallet.devices.some((d) => d.id === device.id)) {
    throw new Error(`Device already registered: ${device.id}`);
  }
  return {
    ...wallet,
    devices: [...wallet.devices, device],
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function removeDevice(wallet: Wallet, deviceId: string): Wallet {
  return {
    ...wallet,
    devices: wallet.devices.filter((d) => d.id !== deviceId),
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function revokeDevice(wallet: Wallet, deviceId: string): Wallet {
  return {
    ...wallet,
    devices: wallet.devices.map((d) => (d.id === deviceId ? { ...d, revokedAt: Date.now() } : d)),
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function addGuardian(wallet: Wallet, guardianId: string): Wallet {
  if (wallet.guardians.includes(guardianId)) return wallet;
  return {
    ...wallet,
    guardians: [...wallet.guardians, guardianId],
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function removeGuardian(wallet: Wallet, guardianId: string): Wallet {
  return {
    ...wallet,
    guardians: wallet.guardians.filter((g) => g !== guardianId),
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function updatePolicy(wallet: Wallet, policyId: string): Wallet {
  return {
    ...wallet,
    policyId,
    updatedAt: Date.now(),
    version: wallet.version + 1,
  };
}

export function getActiveDevices(wallet: Wallet): Device[] {
  return wallet.devices.filter((d) => d.revokedAt === null);
}

export function getDevice(wallet: Wallet, deviceId: string): Device | undefined {
  return wallet.devices.find((d) => d.id === deviceId);
}

export function isDeviceAuthorized(wallet: Wallet, deviceId: string): boolean {
  const device = getDevice(wallet, deviceId);
  return device !== undefined && device.revokedAt === null;
}
