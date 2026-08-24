import {
  type KeymeshTransaction,
  hashKeymeshTransaction,
  validateKeymeshTransaction,
} from '@keymesh/protocol';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  http,
  type Account,
  type Address,
  type Chain,
  type PublicClient,
  type WalletClient,
  bytesToHex,
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  hexToBytes,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { waitForTransactionReceipt } from 'viem/actions';
import { keymeshWalletAbi } from './abi';

/**
 * On-chain device-signed transaction flow (Phase 1.1).
 *
 * MATURITY: experimental. Works against local Anvil; not audited; single-key
 * device ECDSA (no TSS/MPC). Private keys are supplied by the caller as viem
 * `Account` objects — this module never persists or logs key material.
 */

export interface KeymeshSessionConfig {
  /** Deployed KeymeshWallet address. */
  walletAddress: Address;
  chain: Chain;
  rpcUrl: string;
  /**
   * Private key of the authorizing device.
   * LOCAL DEVELOPMENT ONLY in this phase; never persisted or logged here.
   * Phase 2 replaces raw keys with threshold/TSS signers behind this field.
   */
  devicePrivateKey: `0x${string}`;
  /**
   * Account paying gas for submissions; defaults to the device account.
   * Authorization never depends on the relayer's identity.
   */
  relayerAccount?: Account;
  /**
   * Manager account for registerDevice/revokeDevice during Phase 1
   * (transitional device-set control). Omit for read/sign/execute flows.
   */
  managerAccount?: Account;
}

export interface SignedKeymeshTransaction {
  transaction: KeymeshTransaction;
  /** keccak256 of the canonical KEYMESH_TX_V1 encoding — exactly what was signed. */
  digest: `0x${string}`;
  /** 65-byte r||s||v, v normalized to {27, 28} for OpenZeppelin ECDSA.recover. */
  signature: `0x${string}`;
}

export interface ExecutionResult {
  txHash: `0x${string}`;
  status: 'success' | 'reverted';
  nonce: bigint;
  device: Address;
  to: Address;
  value: bigint;
  data: `0x${string}`;
}

/** viem may emit v ∈ {0,1}; OZ ECDSA.recover requires {27,28}. */
export function normalizeVTo2728(signature: `0x${string}`): `0x${string}` {
  const raw = hexToBytes(signature);
  if (raw.length !== 65) throw new Error(`expected 65-byte signature, got ${raw.length}`);
  const v = raw[64];
  if (v === undefined) throw new Error('missing signature v byte');
  if (v <= 1) {
    const fixed = new Uint8Array(raw);
    fixed[64] = v + 27;
    return bytesToHex(fixed);
  }
  if (v === 27 || v === 28) return signature;
  throw new Error(`invalid signature v byte: ${v}`);
}

/**
 * Signs a 32-byte digest with a device key — raw digest signing, no EIP-191
 * prefix — producing r||s||v with low-S normalization and a deterministic
 * RFC-6979 nonce (@noble/curves). Shared by transaction and recovery flows.
 */
export function signDigestWithDeviceKey(
  privateKey: `0x${string}`,
  digest: `0x${string}`
): `0x${string}` {
  const sig = secp256k1.sign(hexToBytes(digest), hexToBytes(privateKey), {
    prehash: false,
    lowS: true,
  });
  const compact = sig.toCompactRawBytes(); // r || s, 64 bytes
  const out = new Uint8Array(65);
  out.set(compact, 0);
  out[64] = sig.recovery + 27;
  return bytesToHex(out);
}

export interface BuildTransactionInput {
  wallet: Address;
  chainId: bigint;
  /** Next expected on-chain nonce (fetched by callers without a local view). */
  nonce: bigint;
  to: Address;
  value: bigint;
  data?: `0x${string}`;
  /** Validity window length; default 3600s when nowSeconds is provided. */
  expiresInSeconds?: number;
  /** Wall clock used for both expiry computation and pre-flight validation. */
  nowSeconds?: bigint;
}

/**
 * Pure transaction constructor shared by the session and tests. Expiry is
 * computed as now + expiresInSeconds (default 3600) and validated inclusive
 * of the same instant.
 */
export function buildKeymeshTransaction(input: BuildTransactionInput): KeymeshTransaction {
  const nowSeconds = input.nowSeconds ?? BigInt(Math.floor(Date.now() / 1000));
  const tx: KeymeshTransaction = {
    wallet: input.wallet,
    chainId: input.chainId,
    nonce: input.nonce,
    to: input.to,
    value: input.value,
    data: input.data ?? '0x',
    expiry: nowSeconds + BigInt(input.expiresInSeconds ?? 3600),
  };
  validateKeymeshTransaction(tx, { nowSeconds });
  return tx;
}

export class KeymeshWalletSession {
  readonly walletAddress: Address;
  readonly chainId: bigint;

  private readonly publicClient: PublicClient;
  private readonly relayerClient: WalletClient;
  private readonly relayerAccount: Account;
  private readonly viemChain: Chain;
  private readonly managerClient: WalletClient | null;
  private readonly managerAccount: Account | null;
  private readonly deviceAccount: Account;
  private readonly devicePrivateKey: `0x${string}`;

  constructor(config: KeymeshSessionConfig) {
    this.walletAddress = config.walletAddress;
    this.chainId = BigInt(config.chain.id);
    this.deviceAccount = privateKeyToAccount(config.devicePrivateKey);
    this.devicePrivateKey = config.devicePrivateKey;
    this.relayerAccount = config.relayerAccount ?? this.deviceAccount;
    this.viemChain = config.chain;

    const transport = http(config.rpcUrl);
    this.publicClient = createPublicClient({ chain: config.chain, transport });
    this.relayerClient = createWalletClient({
      account: this.relayerAccount,
      chain: config.chain,
      transport,
    });
    this.managerClient = config.managerAccount
      ? createWalletClient({ account: config.managerAccount, chain: config.chain, transport })
      : null;
    this.managerAccount = config.managerAccount ?? null;
  }

  // ---------------------------------------------------------------
  // reads
  // ---------------------------------------------------------------

  async getNonce(): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'getNonce',
    });
  }

  async isDeviceAuthorized(device: Address): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'isDeviceAuthorized',
      args: [device],
    });
  }

  // ---------------------------------------------------------------
  // build -> sign -> execute
  // ---------------------------------------------------------------

  async createTransaction(input: {
    to: Address;
    value: bigint;
    data?: `0x${string}`;
    expiresInSeconds?: number;
    /**
     * Clock source for expiry computation. Defaults to wall clock; pass the
     * CHAIN clock when the chain may have been time-traveled (Anvil tests),
     * otherwise every request would expire instantly.
     */
    nowSeconds?: bigint;
  }): Promise<KeymeshTransaction> {
    const nonce = await this.getNonce();
    return buildKeymeshTransaction({
      wallet: this.walletAddress,
      chainId: this.chainId,
      nonce,
      to: input.to,
      value: input.value,
      data: input.data,
      expiresInSeconds: input.expiresInSeconds,
      nowSeconds: input.nowSeconds,
    });
  }

  /**
   * Signs the canonical digest with the device key — raw digest signing, no
   * EIP-191 prefix — producing r||s||v with low-S normalization and a
   * deterministic RFC-6979 nonce (@noble/curves).
   */
  signTransaction(transaction: KeymeshTransaction): SignedKeymeshTransaction {
    validateKeymeshTransaction(transaction);
    const digest = hashKeymeshTransaction(transaction);

    return {
      transaction,
      digest,
      signature: signDigestWithDeviceKey(this.devicePrivateKey, digest),
    };
  }

  async execute(signed: SignedKeymeshTransaction): Promise<ExecutionResult> {
    const calldata = encodeFunctionData({
      abi: keymeshWalletAbi,
      functionName: 'execute',
      args: [
        signed.transaction.wallet,
        signed.transaction.chainId,
        signed.transaction.to,
        signed.transaction.value,
        signed.transaction.data,
        signed.transaction.nonce,
        signed.transaction.expiry,
        signed.signature,
      ],
    });

    const txHash = await this.relayerClient.sendTransaction({
      account: this.relayerAccount,
      chain: this.viemChain,
      to: this.walletAddress,
      data: calldata,
    });
    const receipt = await waitForTransactionReceipt(this.publicClient, { hash: txHash });

    const event = receipt.logs
      .map((log) => {
        try {
          return decodeEventLog({ abi: keymeshWalletAbi, data: log.data, topics: log.topics });
        } catch {
          return null;
        }
      })
      .find((decoded): decoded is Extract<typeof decoded, NonNullable<typeof decoded>> =>
        Boolean(decoded && decoded.eventName === 'TransactionExecuted')
      );

    if (!event || event.eventName !== 'TransactionExecuted') {
      throw new Error('TransactionExecuted event missing from successful receipt');
    }
    if (receipt.status !== 'success') {
      throw new Error(`execute reverted on-chain: ${txHash}`);
    }

    const args = event.args as {
      nonce: bigint;
      device: Address;
      to: Address;
      value: bigint;
      data: `0x${string}`;
    };

    return {
      txHash,
      status: 'success',
      nonce: args.nonce,
      device: args.device,
      to: args.to,
      value: args.value,
      data: args.data ?? '0x',
    };
  }

  // ---------------------------------------------------------------
  // device management (Phase 1: manager-gated)
  // ---------------------------------------------------------------

  async registerDevice(device: Address): Promise<`0x${string}`> {
    return this.sendManager(
      encodeFunctionData({ abi: keymeshWalletAbi, functionName: 'registerDevice', args: [device] })
    );
  }

  async revokeDevice(device: Address): Promise<`0x${string}`> {
    return this.sendManager(
      encodeFunctionData({ abi: keymeshWalletAbi, functionName: 'revokeDevice', args: [device] })
    );
  }

  private async sendManager(data: `0x${string}`): Promise<`0x${string}`> {
    const managerClient = this.managerClient;
    const managerAccount = this.managerAccount;
    if (!managerClient || !managerAccount) {
      throw new Error('managerAccount required for device management calls');
    }
    const txHash = await managerClient.sendTransaction({
      account: managerAccount,
      chain: this.viemChain,
      to: this.walletAddress,
      data,
    });
    const receipt = await waitForTransactionReceipt(this.publicClient, { hash: txHash });
    if (receipt.status !== 'success') throw new Error(`manager call reverted: ${txHash}`);
    return txHash;
  }
}

export function createKeymeshSession(config: KeymeshSessionConfig): KeymeshWalletSession {
  return new KeymeshWalletSession(config);
}

export interface KeymeshWalletDeployInput {
  /** Foundry artifact (`out/KeymeshWallet.sol/KeymeshWallet.json`) fields. */
  artifactAbi: unknown[];
  artifactBytecode: `0x${string}`;
  rpcUrl: string;
  chain: Chain;
  /**
   * Becomes the wallet's BOOTSTRAP-ONLY device-set manager; the role is
   * permanently retired when recovery governance is initialized.
   */
  managerAccount: Account;
  initialDevice: Address;
  /** RecoveryManager contract allowed to apply finalized recoveries. */
  recoveryManagerAddress?: Address;
}

/** Deploys KeymeshWallet with a RecoveryManager pointer (Phase 1.2 wiring). */
export async function deployKeymeshWallet(
  input: KeymeshWalletDeployInput
): Promise<{ address: Address; txHash: `0x${string}` }> {
  const publicClient = createPublicClient({ chain: input.chain, transport: http(input.rpcUrl) });
  const walletClient = createWalletClient({
    account: input.managerAccount,
    chain: input.chain,
    transport: http(input.rpcUrl),
  });

  const recoveryManagerAddress =
    input.recoveryManagerAddress ?? '0x0000000000000000000000000000000000000001';
  const hash = await walletClient.deployContract({
    abi: input.artifactAbi as never,
    bytecode: input.artifactBytecode,
    args: [input.managerAccount.address, input.initialDevice, recoveryManagerAddress],
  });
  const receipt = await waitForTransactionReceipt(publicClient, { hash });
  if (receipt.status !== 'success') throw new Error(`deployment reverted: ${hash}`);
  if (!receipt.contractAddress) throw new Error(`no contractAddress in receipt: ${hash}`);

  return { address: receipt.contractAddress, txHash: hash };
}

export interface KeymeshStackDeployInput {
  rpcUrl: string;
  chain: Chain;
  /** Foundry artifacts for the contracts being deployed. */
  walletArtifact: { abi: unknown[]; bytecode: `0x${string}` };
  recoveryArtifact: { abi: unknown[]; bytecode: `0x${string}` };
  /** Optional Phase 1.3 PolicyManager; wired into the wallet when supplied. */
  policyArtifact?: { abi: unknown[]; bytecode: `0x${string}` };
  /** Deployer becomes the wallet's BOOTSTRAP-ONLY manager. */
  managerAccount: Account;
  initialDevice: Address;
}

export interface KeymeshStack {
  recoveryAddress: Address;
  registryAddress: Address;
  policyAddress: Address | null;
  walletAddress: Address;
}

/**
 * Deploys the KeyMesh stack. The RecoveryManager constructs (and owns) its
 * GuardianRegistry; when a PolicyManager artifact is supplied it is bound to
 * the RecoveryManager (for guardian checks) and consulted by the wallet on
 * every execution. Guardian bootstrap is left to the session classes so
 * callers control quorum/timelock.
 */
export async function deployKeymeshStack(input: KeymeshStackDeployInput): Promise<KeymeshStack> {
  const publicClient = createPublicClient({ chain: input.chain, transport: http(input.rpcUrl) });
  const walletClient = createWalletClient({
    account: input.managerAccount,
    chain: input.chain,
    transport: http(input.rpcUrl),
  });

  async function deploy(
    artifact: {
      abi: unknown[];
      bytecode: `0x${string}`;
    },
    args: unknown[]
  ): Promise<Address> {
    const hash = await walletClient.deployContract({
      abi: artifact.abi as never,
      bytecode: artifact.bytecode,
      args: args as never,
    });
    const receipt = await waitForTransactionReceipt(publicClient, { hash });
    if (receipt.status !== 'success') throw new Error(`deployment reverted: ${hash}`);
    if (!receipt.contractAddress) throw new Error(`no contractAddress in receipt: ${hash}`);
    return receipt.contractAddress;
  }

  // The RecoveryManager constructs its own GuardianRegistry, so the pairing
  // can never be misconfigured.
  const recoveryAddress = await deploy(input.recoveryArtifact, []);
  const registryAddress = (await publicClient.readContract({
    address: recoveryAddress,
    abi: [
      {
        type: 'function',
        name: 'guardianRegistry',
        inputs: [],
        outputs: [{ type: 'address' }],
        stateMutability: 'view',
      },
    ] as never,
    functionName: 'guardianRegistry',
  })) as Address;
  let policyAddress: Address | null = null;
  if (input.policyArtifact) {
    policyAddress = await deploy(input.policyArtifact, [recoveryAddress]);
  }

  const wallet = await deploy(input.walletArtifact, [
    input.managerAccount.address,
    input.initialDevice,
    recoveryAddress,
    policyAddress ?? '0x0000000000000000000000000000000000000000',
  ]);

  return { recoveryAddress, registryAddress, policyAddress, walletAddress: wallet };
}
