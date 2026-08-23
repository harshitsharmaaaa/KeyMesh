import {
  type Device,
  type Wallet,
  addDevice,
  createWallet,
  getActiveDevices,
  getDevice,
  isDeviceAuthorized as isAuthorized,
  removeDevice,
  revokeDevice,
} from '@keymesh/protocol';
import { NotFoundError } from '@keymesh/types';
import type { WalletStorage } from './client';

export interface CreateWalletInput {
  /** Deployed wallet contract address. Placeholder until contracts ship. */
  address?: `0x${string}`;
  initialDevice: CreateDeviceInput;
}

export interface CreateDeviceInput {
  name: string;
  /** Public key only. The SDK never accepts private keys or seed phrases. */
  publicKey: string;
  curve: 'secp256k1' | 'ed25519';
  metadata?: Record<string, unknown>;
}

/**
 * PROTOTYPE: wallet addresses are deterministic placeholders (`0x000...`)
 * until the KeyMesh contracts are deployed. This is intentional and must
 * not be presented to users as a funded address.
 */
const PLACEHOLDER_ADDRESS = `0x${'0'.repeat(40)}` as const;

function newId(): string {
  return crypto.randomUUID();
}

export class WalletApi {
  private readonly storage: WalletStorage;

  constructor(storage: WalletStorage) {
    this.storage = storage;
  }

  async create(input: CreateWalletInput): Promise<Wallet> {
    const device = toDevice(newId(), input.initialDevice);
    const wallet = createWallet({
      id: newId(),
      chainId: 1,
      address: { value: input.address ?? PLACEHOLDER_ADDRESS },
      devices: [device],
      guardians: [],
      policyId: newId(),
    });
    await this.storage.set(wallet);
    return wallet;
  }

  async get(walletId: string): Promise<Wallet> {
    const wallet = await this.storage.get(walletId);
    if (!wallet) throw new NotFoundError('Wallet', walletId);
    return wallet;
  }

  async list(): Promise<Wallet[]> {
    return this.storage.list();
  }

  async delete(walletId: string): Promise<void> {
    await this.get(walletId);
    await this.storage.delete(walletId);
  }

  async save(wallet: Wallet): Promise<void> {
    await this.storage.set(wallet);
  }

  async addDevice(walletId: string, input: CreateDeviceInput): Promise<Wallet> {
    const wallet = await this.get(walletId);
    const updated = addDevice(wallet, toDevice(newId(), input));
    await this.storage.set(updated);
    return updated;
  }

  async revokeDevice(walletId: string, deviceId: string): Promise<Wallet> {
    const wallet = await this.get(walletId);
    if (!getDevice(wallet, deviceId)) throw new NotFoundError('Device', deviceId);
    const updated = revokeDevice(wallet, deviceId);
    await this.storage.set(updated);
    return updated;
  }

  async removeDevice(walletId: string, deviceId: string): Promise<Wallet> {
    const wallet = await this.get(walletId);
    if (!getDevice(wallet, deviceId)) throw new NotFoundError('Device', deviceId);
    const updated = removeDevice(wallet, deviceId);
    await this.storage.set(updated);
    return updated;
  }

  async listDevices(walletId: string): Promise<Device[]> {
    return (await this.get(walletId)).devices;
  }

  async listActiveDevices(walletId: string): Promise<Device[]> {
    return getActiveDevices(await this.get(walletId));
  }

  async isDeviceAuthorized(walletId: string, deviceId: string): Promise<boolean> {
    return isAuthorized(await this.get(walletId), deviceId);
  }
}

function toDevice(id: string, input: CreateDeviceInput): Device {
  const publicKey = (
    input.publicKey.startsWith('0x') ? input.publicKey : `0x${input.publicKey}`
  ) as `0x${string}`;
  return {
    id,
    name: input.name,
    publicKey,
    curve: input.curve,
    authorizedAt: Date.now(),
    revokedAt: null,
    metadata: input.metadata ?? {},
  };
}
