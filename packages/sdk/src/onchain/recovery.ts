import {
  type OnchainRecoveryRequest,
  type OnchainRecoveryStatus,
  RECOVERY_STATUS,
} from '@keymesh/protocol';
import { KeymeshError } from '@keymesh/types';
import {
  http,
  type Account,
  type Address,
  type Chain,
  type PublicClient,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
} from 'viem';
import { waitForTransactionReceipt } from 'viem/actions';
import { guardianRegistryAbi, keymeshWalletAbi, policyManagerAbi, recoveryManagerAbi } from './abi';
import { signDigestWithDeviceKey } from './client';
import { registerDecoderAbis, wrapContractError } from './errors';

/**
 * High-level SDK surface for Phase 1.2 guardian recovery.
 *
 * Authority model (enforced on-chain, reflected here):
 *   - bootstrap   : the wallet's bootstrap manager, exactly once
 *   - initiate    : an active guardian OR authorized device of the wallet
 *   - approve     : active guardians only (EOA call)
 *   - cancel      : authorized devices only (EOA call)
 *   - finalize    : permissionless execution of an approved, timelock-expired
 *                   request; any funded relayer can submit
 *   - guardian set / quorum / timelock management: device-signed through
 *                   KeymeshWallet.execute with the canonical digest
 *
 * Guardians NEVER sign normal transactions; devices never approve recoveries.
 */

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const;
/** Validity window for device-signed governance calls (1 hour). */
const GOVERNANCE_EXPIRY_SECONDS = 3600n;

let decoderRegistered = false;

export interface KeymeshRecoveryConfig {
  walletAddress: Address;
  /** Deployed RecoveryManager contract. */
  recoveryAddress: Address;
  /** Deployed GuardianRegistry contract (owned by the RecoveryManager). */
  registryAddress: Address;
  chain: Chain;
  rpcUrl: string;
  /**
   * Device private key used ONLY for device-signed governance calls
   * (addGuardian/removeGuardian/setQuorum/setTimelock), routed through
   * KeymeshWallet.execute. LOCAL DEVELOPMENT ONLY in this phase; never
   * persisted or logged here.
   */
  governanceDevicePrivateKey?: `0x${string}`;
  /** Relayer paying gas for governance calls; defaults to the device account. */
  relayerAccount?: Account;
}

export interface BootstrapRecoveryInput {
  /** Account holding the wallet's bootstrap-manager role. */
  managerAccount: Account;
  initialGuardians: Address[];
  quorum: number;
  /** Seconds; must be >= MIN_TIMELOCK (1 hour on-chain). */
  timelockSeconds: number;
}

export interface InitiateRecoveryInput {
  /** Active guardian or authorized device account opening the request. */
  account: Account;
  /** Device to revoke at finalization; omit when all devices are lost. */
  replacedDevice?: Address | null;
  newDevice: Address;
}

const STATUS_NAMES: readonly string[] = [
  RECOVERY_STATUS.NONE,
  RECOVERY_STATUS.PENDING,
  RECOVERY_STATUS.QUORUM_REACHED,
  RECOVERY_STATUS.EXECUTABLE,
  RECOVERY_STATUS.EXECUTED,
  RECOVERY_STATUS.CANCELLED,
];

function statusFromDiscriminant(discriminant: number): OnchainRecoveryStatus {
  const name = STATUS_NAMES[discriminant];
  if (name === undefined) throw new Error(`unknown recovery status discriminant ${discriminant}`);
  return name as OnchainRecoveryStatus;
}

interface RawRecoveryRequest {
  wallet: Address;
  initiator: Address;
  replacedDevice: Address;
  newDevice: Address;
  initiatedAt: bigint;
  executeAfter: bigint;
  approvals: bigint;
  quorumSnapshot: bigint;
  status: number;
}

/** viem returns multi-output structs positionally with object ABIs. */
function toRawRecoveryRequest(value: unknown): RawRecoveryRequest {
  const tuple = value as [
    Address,
    Address,
    Address,
    Address,
    bigint,
    bigint,
    bigint,
    bigint,
    number,
  ];
  const [
    wallet,
    initiator,
    replacedDevice,
    newDevice,
    initiatedAt,
    executeAfter,
    approvals,
    quorumSnapshot,
    status,
  ] = tuple;
  return {
    wallet,
    initiator,
    replacedDevice,
    newDevice,
    initiatedAt: BigInt(initiatedAt),
    executeAfter: BigInt(executeAfter),
    approvals: BigInt(approvals),
    quorumSnapshot: BigInt(quorumSnapshot),
    status: Number(status),
  };
}

function toDomainRequest(raw: RawRecoveryRequest, recoveryId: bigint): OnchainRecoveryRequest {
  return {
    recoveryId,
    wallet: raw.wallet,
    initiator: raw.initiator,
    replacedDevice: raw.replacedDevice === ZERO_ADDRESS ? null : (raw.replacedDevice as Address),
    newDevice: raw.newDevice,
    initiatedAt: raw.initiatedAt,
    executeAfter: raw.executeAfter === 0n ? null : raw.executeAfter,
    approvals: Number(raw.approvals),
    quorumSnapshot: Number(raw.quorumSnapshot),
    status: statusFromDiscriminant(Number(raw.status)),
  };
}

export function createKeymeshRecoverySession(
  config: KeymeshRecoveryConfig
): KeymeshRecoverySession {
  return new KeymeshRecoverySession(config);
}

export class KeymeshRecoverySession {
  readonly walletAddress: Address;
  readonly recoveryAddress: Address;
  readonly registryAddress: Address;

  private readonly config: KeymeshRecoveryConfig;
  private readonly publicClient: PublicClient;
  private readonly governanceDevicePrivateKey: `0x${string}` | null;

  constructor(config: KeymeshRecoveryConfig) {
    this.config = config;
    this.walletAddress = config.walletAddress;
    this.recoveryAddress = config.recoveryAddress;
    this.registryAddress = config.registryAddress;
    this.publicClient = createPublicClient({ chain: config.chain, transport: http(config.rpcUrl) });
    this.governanceDevicePrivateKey = config.governanceDevicePrivateKey ?? null;

    if (!decoderRegistered) {
      registerDecoderAbis(
        keymeshWalletAbi,
        recoveryManagerAbi,
        guardianRegistryAbi,
        policyManagerAbi
      );
      decoderRegistered = true;
    }
  }

  // ---------------------------------------------------------------
  // reads
  // ---------------------------------------------------------------

  async isGuardian(guardian: Address): Promise<boolean> {
    try {
      return await this.publicClient.readContract({
        address: this.registryAddress,
        abi: guardianRegistryAbi,
        functionName: 'isGuardian',
        args: [this.walletAddress, guardian],
      });
    } catch (err) {
      throw wrapContractError(err, 'isGuardian');
    }
  }

  async getGuardians(): Promise<Address[]> {
    try {
      const guardians = await this.publicClient.readContract({
        address: this.registryAddress,
        abi: guardianRegistryAbi,
        functionName: 'getGuardians',
        args: [this.walletAddress],
      });
      return [...(guardians as readonly Address[])];
    } catch (err) {
      throw wrapContractError(err, 'getGuardians');
    }
  }

  async getQuorum(): Promise<number> {
    const quorum = await this.publicClient.readContract({
      address: this.recoveryAddress,
      abi: recoveryManagerAbi,
      functionName: 'quorumOf',
      args: [this.walletAddress],
    });
    return Number(quorum);
  }

  async getTimelockSeconds(): Promise<number> {
    const seconds = await this.publicClient.readContract({
      address: this.recoveryAddress,
      abi: recoveryManagerAbi,
      functionName: 'recoveryTimelockSeconds',
      args: [this.walletAddress],
    });
    return Number(seconds);
  }

  async getStatus(): Promise<OnchainRecoveryStatus> {
    const status = await this.publicClient.readContract({
      address: this.recoveryAddress,
      abi: recoveryManagerAbi,
      functionName: 'statusOf',
      args: [this.walletAddress],
    });
    return statusFromDiscriminant(Number(status));
  }

  /** Latest request for the wallet, or null before the first initiation. */
  async getActiveRequest(): Promise<OnchainRecoveryRequest | null> {
    const latestId = await this.publicClient.readContract({
      address: this.recoveryAddress,
      abi: recoveryManagerAbi,
      functionName: 'latestRecoveryIdOf',
      args: [this.walletAddress],
    });
    if (latestId === 0n) return null;
    const raw = toRawRecoveryRequest(
      await this.publicClient.readContract({
        address: this.recoveryAddress,
        abi: recoveryManagerAbi,
        functionName: 'requestById',
        args: [latestId],
      })
    );
    return toDomainRequest(raw, latestId);
  }

  async hasApproved(recoveryId: bigint, guardian: Address): Promise<boolean> {
    try {
      return await this.publicClient.readContract({
        address: this.recoveryAddress,
        abi: recoveryManagerAbi,
        functionName: 'hasApproved',
        args: [recoveryId, guardian],
      });
    } catch (err) {
      throw wrapContractError(err, 'hasApproved');
    }
  }

  async isDeviceAuthorized(device: Address): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'isDeviceAuthorized',
      args: [device],
    });
  }

  async minTimelockSeconds(): Promise<number> {
    const value = await this.publicClient.readContract({
      address: this.recoveryAddress,
      abi: recoveryManagerAbi,
      functionName: 'MIN_TIMELOCK',
    });
    return Number(value);
  }

  // ---------------------------------------------------------------
  // writes — lifecycle
  // ---------------------------------------------------------------

  /** Manager-only, exactly once per wallet. Retires the manager's authority. */
  async bootstrap(input: BootstrapRecoveryInput): Promise<`0x${string}`> {
    if (input.quorum < 1 || input.quorum > input.initialGuardians.length) {
      throw new KeymeshError(
        `invalid threshold: quorum ${input.quorum} must be within 1..${input.initialGuardians.length}`,
        'INVALID_THRESHOLD'
      );
    }
    if (input.timelockSeconds < (await this.minTimelockSeconds())) {
      throw new KeymeshError(
        `timelock ${input.timelockSeconds}s is below the protocol minimum`,
        'TIMELOCK_TOO_SHORT'
      );
    }
    return this.submit(
      input.managerAccount,
      this.recoveryAddress,
      recoveryManagerAbi,
      'bootstrapRecoveryGovernance',
      [
        this.walletAddress,
        input.initialGuardians,
        BigInt(input.quorum),
        BigInt(input.timelockSeconds),
      ]
    );
  }

  /** Guardian or authorized device opens a recovery request. */
  async initiate(input: InitiateRecoveryInput): Promise<`0x${string}`> {
    return this.submit(
      input.account,
      this.recoveryAddress,
      recoveryManagerAbi,
      'initiateRecovery',
      [this.walletAddress, input.replacedDevice ?? ZERO_ADDRESS, input.newDevice]
    );
  }

  /** The calling guardian approves once per recovery. */
  async approve(account: Account): Promise<`0x${string}`> {
    return this.submit(account, this.recoveryAddress, recoveryManagerAbi, 'approveRecovery', [
      this.walletAddress,
    ]);
  }

  /** Authorized devices only: stops a pending/hostile recovery. */
  async cancel(account: Account): Promise<`0x${string}`> {
    return this.submit(account, this.recoveryAddress, recoveryManagerAbi, 'cancelRecovery', [
      this.walletAddress,
    ]);
  }

  /** Permissionless: executes an approved, timelock-elapsed recovery. */
  async finalize(relayerAccount: Account): Promise<`0x${string}`> {
    return this.submit(
      relayerAccount,
      this.recoveryAddress,
      recoveryManagerAbi,
      'finalizeRecovery',
      [this.walletAddress]
    );
  }

  // ---------------------------------------------------------------
  // writes — device-signed governance (through KeymeshWallet.execute)
  // ---------------------------------------------------------------

  async addGuardian(guardian: Address): Promise<`0x${string}`> {
    return this.govern('addGuardian', [this.walletAddress, guardian]);
  }

  async removeGuardian(guardian: Address): Promise<`0x${string}`> {
    return this.govern('removeGuardian', [this.walletAddress, guardian]);
  }

  async setQuorum(quorum: number): Promise<`0x${string}`> {
    if (!Number.isInteger(quorum) || quorum < 1) {
      throw new KeymeshError(`invalid threshold: ${quorum}`, 'INVALID_THRESHOLD');
    }
    return this.govern('setQuorum', [this.walletAddress, BigInt(quorum)]);
  }

  async setTimelock(seconds: number): Promise<`0x${string}`> {
    if (!Number.isInteger(seconds) || seconds < 1) {
      throw new KeymeshError(`invalid timelock seconds: ${seconds}`, 'TIMELOCK_TOO_SHORT');
    }
    return this.govern('setRecoveryTimelock', [this.walletAddress, BigInt(seconds)]);
  }

  /**
   * Routes a RecoveryManager call through KeymeshWallet.execute with a real
   * device signature over the canonical digest — the same path as normal
   * transactions, which is exactly how the contract authenticates it.
   */
  private async govern(
    functionName: 'addGuardian' | 'removeGuardian' | 'setQuorum' | 'setRecoveryTimelock',
    args: unknown[]
  ): Promise<`0x${string}`> {
    const key = this.governanceDevicePrivateKey;
    if (!key) {
      throw new KeymeshError(
        'governanceDevicePrivateKey required for device-signed recovery configuration',
        'UNAUTHORIZED'
      );
    }
    const { privateKeyToAccount } = await import('viem/accounts');

    const nonce = await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'getNonce',
    });
    const chainId = await this.publicClient.getChainId();
    const innerCalldata = encodeFunctionData({
      abi: recoveryManagerAbi,
      functionName,
      args: args as never,
    });
    const expiry = BigInt(Math.floor(Date.now() / 1000)) + GOVERNANCE_EXPIRY_SECONDS;

    // Ask the wallet itself for the exact digest it will verify — one source
    // of truth, zero client-side encoding drift.
    const digest = (await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'transactionDigest',
      args: [
        this.walletAddress,
        BigInt(chainId),
        this.recoveryAddress,
        0n,
        innerCalldata,
        nonce,
        expiry,
      ],
    })) as `0x${string}`;

    const signature = signDigestWithDeviceKey(key, digest);

    const relayer = this.config.relayerAccount ?? privateKeyToAccount(key);
    return this.submit(relayer, this.walletAddress, keymeshWalletAbi, 'execute', [
      this.walletAddress,
      BigInt(chainId),
      this.recoveryAddress,
      0n,
      innerCalldata,
      nonce,
      expiry,
      signature,
    ]);
  }

  // ---------------------------------------------------------------
  // submit plumbing
  // ---------------------------------------------------------------

  private async submit(
    account: Account,
    to: Address,
    abi: typeof keymeshWalletAbi | typeof recoveryManagerAbi | typeof guardianRegistryAbi,
    functionName: string,
    args: unknown[]
  ): Promise<`0x${string}`> {
    const context = String(functionName);
    try {
      // Simulate first so custom errors decode into readable domain errors.
      await this.publicClient.simulateContract({
        address: to,
        abi,
        functionName: functionName as never,
        args: args as never,
        account,
      });
    } catch (err) {
      throw wrapContractError(err, context);
    }

    const calldata = encodeFunctionData({
      abi,
      functionName: functionName as never,
      args: args as never,
    });

    const walletClient = createWalletClient({
      account,
      chain: this.config.chain,
      transport: http(this.config.rpcUrl),
    });
    let hash: `0x${string}`;
    try {
      hash = await walletClient.sendTransaction({
        account,
        chain: this.config.chain,
        to,
        data: calldata,
      });
      const receipt = await waitForTransactionReceipt(this.publicClient, { hash });
      if (receipt.status !== 'success') {
        throw new Error(`transaction reverted on-chain: ${hash}`);
      }
      return hash;
    } catch (err) {
      if ((err as { name?: string })?.name === 'ContractCallError') throw err;
      throw wrapContractError(err, context);
    }
  }
}
