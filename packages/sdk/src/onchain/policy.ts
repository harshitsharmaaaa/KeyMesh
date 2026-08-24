import {
  AUTHORIZATION_MODES,
  type AuthorizationMode,
  type PolicyConfig,
  TXN_AUTHORIZATION_STATUSES,
  type TransactionAuthorization,
} from '@keymesh/protocol';
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
import { keymeshWalletAbi, policyManagerAbi } from './abi';
import { signDigestWithDeviceKey } from './client';
import { registerDecoderAbis, wrapContractError } from './errors';

/**
 * High-level SDK surface for Phase 1.3 transaction authorization policies.
 *
 * Authority model (enforced on-chain):
 *   - reads / previews            : permissionless
 *   - requestAuthorization        : an authorized DEVICE of the wallet (EOA call)
 *   - approveTransaction          : active guardians of the wallet (EOA call)
 *   - cancelAuthorization         : authorized devices only
 *   - configuration changes       : executed THROUGH KeymeshWallet.execute by a
 *                                   device signature AND pre-approved by a
 *                                   guardian transaction authorization bound to
 *                                   that exact digest (structural anti-downgrade
 *                                   rule inside PolicyManager).
 *
 * No TSS/MPC here; modes are limited to DEVICE_ONLY / DEVICE_PLUS_GUARDIANS.
 */

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const;
/** Validity window for device-signed executions built by this session. */
const EXECUTION_EXPIRY_SECONDS = 3600n;

let decoderRegistered = false;

export interface KeymeshPolicyConfig {
  walletAddress: Address;
  policyAddress: Address;
  chain: Chain;
  rpcUrl: string;
  /**
   * Device private key used to OPEN authorization requests and to SIGN
   * governed policy-change executions. LOCAL DEVELOPMENT ONLY in this phase;
   * never persisted or logged here.
   */
  governanceDevicePrivateKey?: `0x${string}`;
  /** Relayer paying gas; defaults to the derived device account. */
  relayerAccount?: Account;
}

export interface ConfigurePolicyInput {
  defaultMode: AuthorizationMode;
  valueThresholdWei: string;
  guardianApprovalsRequired: number;
}

/** Handle returned by propose* methods; required by the matching execute*. */
export interface GovernedProposal {
  digest: `0x${string}`;
  nonce: bigint;
  expiry: bigint;
}

export interface PolicyTxInput {
  to: Address;
  /** Wei as decimal string or bigint. */
  valueWei?: string | bigint;
  data?: `0x${string}`;
  expiresInSeconds?: number;
}

const MODE_NAMES = ['device_only', 'device_plus_guardians'] as const;
const STATUS_NAMES = ['none', 'pending', 'authorized', 'executed', 'cancelled'] as const;

function modeFromDiscriminant(value: number): AuthorizationMode {
  const name = MODE_NAMES[value];
  if (name === undefined) throw new Error(`unknown authorization mode ${value}`);
  return name;
}

function statusFromDiscriminant(value: number): TransactionAuthorization['status'] {
  const name = STATUS_NAMES[value];
  if (name === undefined) throw new Error(`unknown txn-auth status ${value}`);
  return name;
}

function wei(value: string | bigint | undefined): bigint {
  if (value === undefined || value === '') return 0n;
  return typeof value === 'bigint' ? value : BigInt(value);
}

export class KeymeshPolicySession {
  readonly walletAddress: Address;
  readonly policyAddress: Address;

  private readonly config: KeymeshPolicyConfig;
  private readonly publicClient: PublicClient;

  constructor(config: KeymeshPolicyConfig) {
    this.config = config;
    this.walletAddress = config.walletAddress;
    this.policyAddress = config.policyAddress;
    this.publicClient = createPublicClient({ chain: config.chain, transport: http(config.rpcUrl) });

    if (!decoderRegistered) {
      registerDecoderAbis(keymeshWalletAbi, policyManagerAbi);
      decoderRegistered = true;
    }
  }

  // ---------------------------------------------------------------
  // reads
  // ---------------------------------------------------------------

  async getPolicyConfig(): Promise<PolicyConfig> {
    try {
      // Multi-output reads come back positionally.
      const tuple = (await this.publicClient.readContract({
        address: this.policyAddress,
        abi: policyManagerAbi,
        functionName: 'policyOf',
        args: [this.walletAddress],
      })) as [number, bigint, number, bigint];
      const [defaultMode, valueThreshold, guardianApprovalsRequired, version] = tuple;
      return {
        defaultMode: modeFromDiscriminant(Number(defaultMode)),
        valueThresholdWei: valueThreshold.toString(),
        guardianApprovalsRequired: Number(guardianApprovalsRequired),
        version: Number(version),
      };
    } catch (err) {
      throw wrapContractError(err, 'policyOf');
    }
  }

  async isRestrictedDestination(destination: Address): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.policyAddress,
      abi: policyManagerAbi,
      functionName: 'isRestrictedDestination',
      args: [this.walletAddress, destination],
    });
  }

  async isRestrictedSelector(selector: `0x${string}`): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.policyAddress,
      abi: policyManagerAbi,
      functionName: 'isRestrictedSelector',
      args: [this.walletAddress, selector],
    });
  }

  /** Authoritative on-chain classification for a hypothetical transaction. */
  async evaluateAuthorization(tx: PolicyTxInput): Promise<AuthorizationMode> {
    const discriminant = await this.publicClient.readContract({
      address: this.policyAddress,
      abi: policyManagerAbi,
      functionName: 'evaluateAuthorization',
      args: [this.walletAddress, tx.to, wei(tx.valueWei), tx.data ?? '0x'],
    });
    return modeFromDiscriminant(Number(discriminant));
  }

  /** Authorization record for a digest, or null when none exists. */
  async getAuthorization(digest: `0x${string}`): Promise<TransactionAuthorization | null> {
    const tuple = (await this.publicClient.readContract({
      address: this.policyAddress,
      abi: policyManagerAbi,
      functionName: 'authorizationOf',
      args: [digest],
    })) as unknown as [Address, Address, bigint, bigint, bigint, bigint, number];
    const [wallet, requester, requestedAt, policyVersion, approvals, approvalsRequired, status] =
      tuple;
    const statusName = statusFromDiscriminant(Number(status));
    if (statusName === TXN_AUTHORIZATION_STATUSES.NONE && requester === ZERO_ADDRESS) return null;
    return {
      digest,
      wallet,
      requester,
      requestedAt: Number(requestedAt),
      policyVersion: Number(policyVersion),
      approvals: Number(approvals),
      approvalsRequired: Number(approvalsRequired),
      status: statusName,
    };
  }

  async hasTransactionApproval(digest: `0x${string}`, guardian: Address): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.policyAddress,
      abi: policyManagerAbi,
      functionName: 'hasTransactionApproval',
      args: [digest, guardian],
    });
  }

  // ---------------------------------------------------------------
  // digest construction (binds wallet, chainId, nonce, to, value, data, expiry)
  // ---------------------------------------------------------------

  async buildDigest(tx: PolicyTxInput): Promise<`0x${string}`> {
    const nonce = await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'getNonce',
    });
    const chainId = await this.publicClient.getChainId();
    const chainNow = await this.chainNowSeconds();
    const expiry = chainNow + BigInt(tx.expiresInSeconds ?? Number(EXECUTION_EXPIRY_SECONDS));
    return this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'transactionDigest',
      args: [
        this.walletAddress,
        BigInt(chainId),
        tx.to,
        wei(tx.valueWei),
        tx.data ?? '0x',
        nonce,
        expiry,
      ],
    });
  }

  // ---------------------------------------------------------------
  // lifecycle — authorization requests & guardian approvals
  // ---------------------------------------------------------------

  /**
   * An authorized device opens a guardian authorization request bound to the
   * exact digest of `tx`. Returns the digest plus the nonce/expiry used so
   * the caller can later sign the IDENTICAL transaction.
   */
  async requestAuthorization(
    account: Account,
    tx: PolicyTxInput
  ): Promise<{ digest: `0x${string}`; nonce: bigint; expiry: bigint }> {
    const nonce = await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'getNonce',
    });
    const chainId = await this.publicClient.getChainId();
    const expiry =
      (await this.chainNowSeconds()) +
      BigInt(tx.expiresInSeconds ?? Number(EXECUTION_EXPIRY_SECONDS));
    const digest = (await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'transactionDigest',
      args: [
        this.walletAddress,
        BigInt(chainId),
        tx.to,
        wei(tx.valueWei),
        tx.data ?? '0x',
        nonce,
        expiry,
      ],
    })) as `0x${string}`;

    await this.submit(account, this.policyAddress, 'requestAuthorization', [
      this.walletAddress,
      digest,
    ]);
    return { digest, nonce, expiry };
  }

  /**
   * Opens an authorization request for an ALREADY-SIGNED digest (e.g. built
   * by KeymeshWalletSession), keeping request and execution byte-identical.
   */
  async requestAuthorizationForDigest(account: Account, digest: `0x${string}`): Promise<void> {
    await this.submit(account, this.policyAddress, 'requestAuthorization', [
      this.walletAddress,
      digest,
    ]);
  }

  /** The calling guardian approves the exact digest (once). */
  async approveTransaction(
    guardianAccount: Account,
    digest: `0x${string}`
  ): Promise<`0x${string}`> {
    return this.submit(guardianAccount, this.policyAddress, 'approveTransaction', [
      this.walletAddress,
      digest,
    ]);
  }

  /** Authorized devices may abort a pending/approved-but-unexecuted request. */
  async cancelAuthorization(account: Account, digest: `0x${string}`): Promise<`0x${string}`> {
    return this.submit(account, this.policyAddress, 'cancelAuthorization', [
      this.walletAddress,
      digest,
    ]);
  }

  // ---------------------------------------------------------------
  // governed policy administration (two-phase, guardian-approved)
  // ---------------------------------------------------------------

  /** Phase A: open the guardian authorization for this configuration change. */
  async proposeConfigurePolicy(input: ConfigurePolicyInput): Promise<GovernedProposal> {
    return this.proposeGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'configurePolicy',
        args: [
          this.walletAddress,
          AUTHORIZATION_MODE_DISCRIMINANT[input.defaultMode],
          BigInt(input.valueThresholdWei),
          Number(input.guardianApprovalsRequired),
        ],
      })
    );
  }

  /** Phase B: execute an already-approved configuration change. */
  async executeConfigurePolicy(
    input: ConfigurePolicyInput,
    proposal: GovernedProposal
  ): Promise<`0x${string}`> {
    return this.submitGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'configurePolicy',
        args: [
          this.walletAddress,
          AUTHORIZATION_MODE_DISCRIMINANT[input.defaultMode],
          BigInt(input.valueThresholdWei),
          Number(input.guardianApprovalsRequired),
        ],
      }),
      proposal
    );
  }

  async proposeSetValueThreshold(thresholdWei: string): Promise<GovernedProposal> {
    return this.proposeGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setValueThreshold',
        args: [this.walletAddress, BigInt(thresholdWei)],
      })
    );
  }

  async executeSetValueThreshold(
    thresholdWei: string,
    proposal: GovernedProposal
  ): Promise<`0x${string}`> {
    return this.submitGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setValueThreshold',
        args: [this.walletAddress, BigInt(thresholdWei)],
      }),
      proposal
    );
  }

  async proposeSetDestinationRestriction(
    destination: Address,
    restricted: boolean
  ): Promise<GovernedProposal> {
    return this.proposeGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setDestinationRestriction',
        args: [this.walletAddress, destination, restricted],
      })
    );
  }

  async executeSetDestinationRestriction(
    destination: Address,
    restricted: boolean,
    proposal: GovernedProposal
  ): Promise<`0x${string}`> {
    return this.submitGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setDestinationRestriction',
        args: [this.walletAddress, destination, restricted],
      }),
      proposal
    );
  }

  async proposeSetSelectorRestriction(
    selector: `0x${string}`,
    restricted: boolean
  ): Promise<GovernedProposal> {
    return this.proposeGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setSelectorRestriction',
        args: [this.walletAddress, selector, restricted],
      })
    );
  }

  async executeSetSelectorRestriction(
    selector: `0x${string}`,
    restricted: boolean,
    proposal: GovernedProposal
  ): Promise<`0x${string}`> {
    return this.submitGoverned(
      encodeFunctionData({
        abi: policyManagerAbi,
        functionName: 'setSelectorRestriction',
        args: [this.walletAddress, selector, restricted],
      }),
      proposal
    );
  }

  // ---------------------------------------------------------------
  // internals
  // ---------------------------------------------------------------

  /**
   * Current wallet nonce AND chain clock. Expiries MUST derive from the
   * chain clock: Anvil time travel (`evm_increaseTime`) shifts the chain
   * ahead of the wall clock, which would make every request expire
   * instantly if built from Date.now().
   */
  private async walletHead(): Promise<{ nonce: bigint; chainNow: bigint }> {
    const [nonce, block] = await Promise.all([
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: keymeshWalletAbi,
        functionName: 'getNonce',
      }),
      this.publicClient.getBlock({ blockTag: 'latest' }),
    ]);
    return { nonce, chainNow: block.timestamp };
  }

  /**
   * Chain clock (latest block timestamp). Expiries MUST derive from it:
   * Anvil time travel (`evm_increaseTime`) shifts the chain ahead of the
   * wall clock, which would make requests expire instantly if built from
   * Date.now().
   */
  private async chainNowSeconds(): Promise<bigint> {
    const block = await this.publicClient.getBlock({ blockTag: 'latest' });
    return block.timestamp;
  }

  private get deviceKey(): `0x${string}` {
    const key = this.config.governanceDevicePrivateKey;
    if (!key) {
      throw new Error('governanceDevicePrivateKey required for policy administration');
    }
    return key;
  }

  private async proposeGoverned(innerCalldata: `0x${string}`): Promise<GovernedProposal> {
    const { privateKeyToAccount } = await import('viem/accounts');
    const device = privateKeyToAccount(this.deviceKey);
    const nonce = await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'getNonce',
    });
    const chainId = await this.publicClient.getChainId();
    const expiry = (await this.chainNowSeconds()) + EXECUTION_EXPIRY_SECONDS;
    const digest = (await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'transactionDigest',
      args: [
        this.walletAddress,
        BigInt(chainId),
        this.policyAddress,
        0n,
        innerCalldata,
        nonce,
        expiry,
      ],
    })) as `0x${string}`;

    await this.submit(device, this.policyAddress, 'requestAuthorization', [
      this.walletAddress,
      digest,
    ]);
    return { digest, nonce, expiry };
  }

  private async submitGoverned(
    innerCalldata: `0x${string}`,
    proposal: GovernedProposal
  ): Promise<`0x${string}`> {
    const { privateKeyToAccount } = await import('viem/accounts');
    const key = this.deviceKey;
    const device = privateKeyToAccount(key);
    const chainId = await this.publicClient.getChainId();

    // Rebuild the digest from the PROPOSAL's nonce/expiry so execution is
    // byte-identical to what the guardians approved.
    const digest = (await this.publicClient.readContract({
      address: this.walletAddress,
      abi: keymeshWalletAbi,
      functionName: 'transactionDigest',
      args: [
        this.walletAddress,
        BigInt(chainId),
        this.policyAddress,
        0n,
        innerCalldata,
        proposal.nonce,
        proposal.expiry,
      ],
    })) as `0x${string}`;
    if (digest !== proposal.digest) {
      throw new Error('wallet state changed since proposal; re-propose the change');
    }
    const signature = signDigestWithDeviceKey(key, digest);

    const relayer = this.config.relayerAccount ?? device;
    return this.submitRaw(
      relayer,
      this.walletAddress,
      'execute',
      [
        this.walletAddress,
        BigInt(chainId),
        this.policyAddress,
        0n,
        innerCalldata,
        proposal.nonce,
        proposal.expiry,
        signature,
      ],
      keymeshWalletAbi
    );
  }

  private async submit(
    account: Account,
    to: Address,
    functionName: string,
    args: unknown[]
  ): Promise<`0x${string}`> {
    const abi = to === this.policyAddress ? policyManagerAbi : keymeshWalletAbi;
    return this.submitRaw(account, to, functionName, args, abi);
  }

  private async submitRaw(
    account: Account,
    to: Address,
    functionName: string,
    args: unknown[],
    abi: typeof keymeshWalletAbi | typeof policyManagerAbi = policyManagerAbi
  ): Promise<`0x${string}`> {
    const context = String(functionName);
    try {
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
      if (receipt.status !== 'success') throw new Error(`transaction reverted on-chain: ${hash}`);
      return hash;
    } catch (err) {
      if ((err as { name?: string })?.name === 'ContractCallError') throw err;
      throw wrapContractError(err, context);
    }
  }
}

const AUTHORIZATION_MODE_DISCRIMINANT: Record<AuthorizationMode, number> = {
  [AUTHORIZATION_MODES.DEVICE_ONLY]: 0,
  [AUTHORIZATION_MODES.DEVICE_PLUS_GUARDIANS]: 1,
};

export function createKeymeshPolicySession(config: KeymeshPolicyConfig): KeymeshPolicySession {
  return new KeymeshPolicySession(config);
}
