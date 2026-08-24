import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  type KeymeshPolicySession,
  createKeymeshPolicySession,
  createKeymeshRecoverySession,
  createKeymeshSession,
  deployKeymeshStack,
} from '@keymesh/sdk';
import { NextResponse } from 'next/server';
import { http, type Address, createPublicClient, createWalletClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

export const dynamic = 'force-dynamic';

/**
 * Phase 1.3 policy console endpoint: drives the REAL on-chain policy engine
 * (configuration via guardian-approved administration + per-digest
 * transaction authorizations) through @keymesh/sdk against LOCAL Anvil.
 *
 * Keys are PUBLIC deterministic Anvil fixture keys (test networks only) and
 * never leave this module. The browser only sees addresses and state.
 */
const MANAGER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const DEVICE_A_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const DEVICE_B_KEY = '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e' as const;
const GUARDIAN_1_KEY =
  '0x2222222222222222222222222222222222222222222222222222222222222222' as const;
const GUARDIAN_2_KEY =
  '0x3333333333333333333333333333333333333333333333333333333333333333' as const;
const GUARDIAN_3_KEY =
  '0x4444444444444444444444444444444444444444444444444444444444444444' as const;

const RPC_URL = process.env.KEYMESH_DEMO_RPC_URL ?? 'http://127.0.0.1:8545';
const chain = { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } };

interface DemoStack {
  walletAddress: Address;
  recoveryAddress: Address;
  registryAddress: Address;
  policyAddress: Address;
}

/** Handle for the last requested high-value transfer (digest + binding). */
interface PendingHandle {
  digest: `0x${string}`;
  nonce: bigint;
  expiry: bigint;
}

let cachedStack: (DemoStack & { pending?: PendingHandle }) | null = null;

async function loadArtifact(name: string): Promise<{ abi: unknown[]; bytecode: `0x${string}` }> {
  const artifactPath = path.resolve(
    process.cwd(),
    '..',
    '..',
    'contracts',
    'ethereum',
    'out',
    `${name}.sol`,
    `${name}.json`
  );
  const parsed = JSON.parse(await readFile(artifactPath, 'utf8')) as {
    abi?: unknown[];
    bytecode?: { object?: `0x${string}` };
  };
  if (!parsed.abi?.length || !parsed.bytecode?.object) {
    throw new Error(
      `Foundry artifact missing at ${artifactPath}. Run \`forge build --root contracts/ethereum\` first.`
    );
  }
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
}

function policySession(stack: DemoStack): KeymeshPolicySession {
  return createKeymeshPolicySession({
    walletAddress: stack.walletAddress,
    policyAddress: stack.policyAddress,
    chain,
    rpcUrl: RPC_URL,
    governanceDevicePrivateKey: DEVICE_A_KEY,
    relayerAccount: privateKeyToAccount(MANAGER_KEY),
  });
}

async function getStack(): Promise<DemoStack & { pending?: PendingHandle }> {
  if (cachedStack) return cachedStack;
  const [walletArtifact, recoveryArtifact, policyArtifact] = await Promise.all([
    loadArtifact('KeymeshWallet'),
    loadArtifact('RecoveryManager'),
    loadArtifact('PolicyManager'),
  ]);
  const manager = privateKeyToAccount(MANAGER_KEY);
  const stack = await deployKeymeshStack({
    rpcUrl: RPC_URL,
    chain,
    walletArtifact,
    recoveryArtifact,
    policyArtifact,
    managerAccount: manager,
    initialDevice: privateKeyToAccount(DEVICE_A_KEY).address,
  });

  // Fund gas accounts with deterministic local fixture ETH only.
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
  const relayer = createWalletClient({ account: manager, chain, transport: http(RPC_URL) });
  for (const account of [
    privateKeyToAccount(GUARDIAN_1_KEY),
    privateKeyToAccount(GUARDIAN_2_KEY),
    privateKeyToAccount(GUARDIAN_3_KEY),
  ]) {
    const hash = await relayer.sendTransaction({ to: account.address, value: 10n ** 17n });
    await publicClient.waitForTransactionReceipt({ hash });
  }

  await createKeymeshRecoverySession({
    walletAddress: stack.walletAddress,
    recoveryAddress: stack.recoveryAddress,
    registryAddress: stack.registryAddress,
    chain,
    rpcUrl: RPC_URL,
  }).bootstrap({
    managerAccount: manager,
    initialGuardians: [
      privateKeyToAccount(GUARDIAN_1_KEY).address,
      privateKeyToAccount(GUARDIAN_2_KEY).address,
      privateKeyToAccount(GUARDIAN_3_KEY).address,
    ],
    quorum: 2,
    timelockSeconds: 3600,
  });

  const result: DemoStack & { pending?: PendingHandle } = {
    walletAddress: stack.walletAddress,
    recoveryAddress: stack.recoveryAddress,
    registryAddress: stack.registryAddress,
    policyAddress: stack.policyAddress as Address,
  };
  cachedStack = result;
  return result;
}

async function buildState(stack: DemoStack & { pending?: PendingHandle }) {
  const policy = policySession(stack);
  const config = await policy.getPolicyConfig();
  const auth =
    stack.pending?.digest !== undefined
      ? await policy.getAuthorization(stack.pending.digest)
      : null;
  return {
    ok: true as const,
    walletAddress: stack.walletAddress,
    currentDevice: privateKeyToAccount(DEVICE_A_KEY).address,
    policyVersion: config.version,
    defaultMode: config.defaultMode,
    valueThresholdWei: config.valueThresholdWei,
    guardianApprovalsRequired: config.guardianApprovalsRequired,
    restrictedDestinations: [
      {
        address: privateKeyToAccount(DEVICE_B_KEY).address,
        restricted: await policy.isRestrictedDestination(privateKeyToAccount(DEVICE_B_KEY).address),
      },
    ],
    authorization:
      auth === null
        ? null
        : {
            digest: auth.digest,
            status: auth.status,
            approvals: auth.approvals,
            approvalsRequired: auth.approvalsRequired,
            policyVersion: auth.policyVersion,
          },
    chainNow: String((await publicClientNow()).timestamp),
  };

  async function publicClientNow() {
    return createPublicClient({ chain, transport: http(RPC_URL) }).getBlock({
      blockTag: 'latest',
    });
  }
}

export async function GET() {
  try {
    const stack = (await getStack()) as DemoStack & { pending?: PendingHandle };
    return NextResponse.json(await buildState(stack));
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
}

const ACTIONS = new Set([
  'configure',
  'set-threshold',
  'add-restricted',
  'remove-restricted',
  'request-high-value',
  'approve-high-value',
  'execute-high-value',
  'reset',
]);

export async function POST(request: Request) {
  let action = '';
  try {
    const body = (await request.json()) as { action?: string };
    action = body.action ?? '';
    if (!ACTIONS.has(action)) return fail(`unknown action: ${action || '(none)'}`);
    if (!(await nodeReachable())) {
      return fail(`no Ethereum node at ${RPC_URL}. Start one with \`anvil\`, then retry.`);
    }

    const live = (await getStack()) as DemoStack & { pending?: PendingHandle };
    const policy = policySession(live);
    const g1 = privateKeyToAccount(GUARDIAN_1_KEY);
    const g2 = privateKeyToAccount(GUARDIAN_2_KEY);

    let detail = '';
    switch (action) {
      case 'reset': {
        cachedStack = null;
        detail = 'demo stack discarded; a fresh wallet deploys on next refresh';
        break;
      }
      case 'configure': {
        // Bootstrap semantics: the wallet's policy is still unconfigured, so
        // this first governed change needs a single guardian approval; after
        // that the configured quorum applies to every further change.
        const input = {
          defaultMode: 'device_only' as const,
          valueThresholdWei: '500000000000000000', // 0.5 ETH
          guardianApprovalsRequired: 2,
        };
        const proposal = await policy.proposeConfigurePolicy(input);
        live.pending = { digest: proposal.digest, nonce: proposal.nonce, expiry: proposal.expiry };
        await policy.approveTransaction(g1, proposal.digest);
        await policy.executeConfigurePolicy(input, proposal);
        detail = 'policy configured through guardian-approved administration (v1)';
        break;
      }
      case 'set-threshold': {
        const input = { thresholdWei: '100000000000000000' }; // 0.1 ETH
        const proposal = await policy.proposeSetValueThreshold(input.thresholdWei);
        live.pending = { digest: proposal.digest, nonce: proposal.nonce, expiry: proposal.expiry };
        await policy.approveTransaction(g1, proposal.digest);
        await policy.approveTransaction(g2, proposal.digest);
        await policy.executeSetValueThreshold(input.thresholdWei, proposal);
        detail = `value threshold lowered to ${input.thresholdWei} wei via governed change`;
        break;
      }
      case 'add-restricted': {
        const proposal = await policy.proposeSetDestinationRestriction(
          privateKeyToAccount(DEVICE_B_KEY).address,
          true
        );
        live.pending = { digest: proposal.digest, nonce: proposal.nonce, expiry: proposal.expiry };
        await policy.approveTransaction(g1, proposal.digest);
        await policy.approveTransaction(g2, proposal.digest);
        await policy.executeSetDestinationRestriction(
          privateKeyToAccount(DEVICE_B_KEY).address,
          true,
          proposal
        );
        detail = 'device B added to restricted destinations';
        break;
      }
      case 'remove-restricted': {
        const proposal = await policy.proposeSetDestinationRestriction(
          privateKeyToAccount(DEVICE_B_KEY).address,
          false
        );
        live.pending = { digest: proposal.digest, nonce: proposal.nonce, expiry: proposal.expiry };
        await policy.approveTransaction(g1, proposal.digest);
        await policy.approveTransaction(g2, proposal.digest);
        await policy.executeSetDestinationRestriction(
          privateKeyToAccount(DEVICE_B_KEY).address,
          false,
          proposal
        );
        detail = 'device B removed from restricted destinations';
        break;
      }
      case 'request-high-value': {
        // 0.7 ETH transfer above the 0.5 ETH default threshold, requested by
        // the authorized device itself (EOA call).
        const handle = await policy.requestAuthorization(privateKeyToAccount(DEVICE_A_KEY), {
          to: privateKeyToAccount(GUARDIAN_3_KEY).address,
          valueWei: '700000000000000000',
          expiresInSeconds: 3600,
        });
        live.pending = handle;
        detail = 'guardian authorization requested for high-value transfer';
        break;
      }
      case 'approve-high-value': {
        if (!live.pending) throw new Error('no pending request; request one first');
        await policy.approveTransaction(g1, live.pending.digest);
        detail = 'guardian approval recorded';
        break;
      }
      case 'execute-high-value': {
        if (!live.pending) throw new Error('no request digest');
        const auth = await policy.getAuthorization(live.pending.digest);
        if (!auth || auth.status !== 'authorized') {
          throw new Error(
            `digest is '${auth?.status ?? 'none'}'; open a request and collect the quorum first`
          );
        }
        // Rebuild the EXACT transaction bound to the digest and sign it with
        // the same device key that opened the request.
        const session = createKeymeshSession({
          walletAddress: live.walletAddress,
          chain,
          rpcUrl: RPC_URL,
          devicePrivateKey: DEVICE_A_KEY,
          relayerAccount: privateKeyToAccount(MANAGER_KEY),
        });
        const tx = {
          wallet: live.walletAddress,
          chainId: BigInt(chain.id),
          nonce: live.pending.nonce,
          to: privateKeyToAccount(GUARDIAN_3_KEY).address,
          value: 700000000000000000n,
          data: '0x' as const,
          expiry: live.pending.expiry,
        };
        const signed = session.signTransaction(tx);
        if (signed.digest !== live.pending.digest) {
          throw new Error('reconstructed digest mismatch; request a fresh authorization');
        }
        const exec = await session.execute(signed);
        detail = `high-value transfer executed (${exec.txHash})`;
        break;
      }
    }

    const state = await buildState(live);
    return NextResponse.json({ ...state, lastAction: { action, detail } });
  } catch (err) {
    const message =
      err && typeof err === 'object' && 'message' in err
        ? String((err as { message: string }).message)
        : String(err);
    return fail(`action '${action}' failed: ${message}`);
  }
}

function fail(error: string) {
  return NextResponse.json({ ok: false as const, error }, { status: 500 });
}

async function nodeReachable(): Promise<boolean> {
  try {
    await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
      signal: AbortSignal.timeout(1500),
    });
    return true;
  } catch {
    return false;
  }
}
