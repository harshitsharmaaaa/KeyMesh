import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  type KeymeshRecoverySession,
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
 * Phase 1.2 recovery demo endpoint: drives the REAL on-chain guardian
 * recovery flow (bootstrap -> initiate -> approve -> timelock -> finalize)
 * through the @keymesh/sdk against a LOCAL Anvil node. Entirely server-side.
 *
 * Keys below are PUBLIC deterministic Anvil fixture keys (test networks only).
 * They never leave this module — the browser receives addresses and state
 * only. This is a local development demo, NOT custody.
 */
const MANAGER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const DEVICE_A_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const DEVICE_B_KEY = '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e' as const;
const DEVICE_C_KEY = '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
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
}

// Dev-server cache so actions operate on the SAME deployed stack. Restarting
// the dashboard or Anvil resets it; nothing persists anywhere.
let cachedStack: DemoStack | null = null;

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

async function getStack(): Promise<DemoStack> {
  if (cachedStack) return cachedStack;
  const [walletArtifact, recoveryArtifact] = await Promise.all([
    loadArtifact('KeymeshWallet'),
    loadArtifact('RecoveryManager'),
  ]);
  const manager = privateKeyToAccount(MANAGER_KEY);
  const stack = await deployKeymeshStack({
    rpcUrl: RPC_URL,
    chain,
    walletArtifact,
    recoveryArtifact,
    managerAccount: manager,
    initialDevice: privateKeyToAccount(DEVICE_A_KEY).address,
  });

  // Fund gas accounts with deterministic local ETH (Anvil fixture balances).
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
  const relayer = createWalletClient({ account: manager, chain, transport: http(RPC_URL) });
  for (const account of [
    privateKeyToAccount(GUARDIAN_1_KEY),
    privateKeyToAccount(GUARDIAN_2_KEY),
    privateKeyToAccount(GUARDIAN_3_KEY),
    privateKeyToAccount(DEVICE_B_KEY),
    privateKeyToAccount(DEVICE_C_KEY),
  ]) {
    const hash = await relayer.sendTransaction({ to: account.address, value: 10n ** 17n });
    await publicClient.waitForTransactionReceipt({ hash });
  }

  // Register a healthy secondary device BEFORE bootstrap (multi-device
  // wallet); afterwards the manager can no longer change devices.
  await createKeymeshSession({
    walletAddress: stack.walletAddress,
    chain,
    rpcUrl: RPC_URL,
    devicePrivateKey: DEVICE_A_KEY,
    relayerAccount: manager,
    managerAccount: manager,
  }).registerDevice(privateKeyToAccount(DEVICE_B_KEY).address);

  // Bootstrap the initial guardian set: 3 guardians, 2 required, 1h timelock
  // (protocol minimum, short for local demos). This permanently retires the
  // manager's authority over the device set.
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

  cachedStack = stack;
  return stack;
}

function recoverySession(stack: DemoStack): KeymeshRecoverySession {
  return createKeymeshRecoverySession({
    walletAddress: stack.walletAddress,
    recoveryAddress: stack.recoveryAddress,
    registryAddress: stack.registryAddress,
    chain,
    rpcUrl: RPC_URL,
  });
}

async function buildState(stack: DemoStack) {
  const recovery = recoverySession(stack);
  const request = await recovery.getActiveRequest();
  const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
  const block = await publicClient.getBlock({ blockTag: 'latest' });
  return {
    ok: true as const,
    walletAddress: stack.walletAddress,
    devices: {
      current: privateKeyToAccount(DEVICE_A_KEY).address,
      secondary: privateKeyToAccount(DEVICE_B_KEY).address,
      replacement: privateKeyToAccount(DEVICE_C_KEY).address,
      currentAuthorized: await recovery.isDeviceAuthorized(
        privateKeyToAccount(DEVICE_A_KEY).address
      ),
      replacementAuthorized: await recovery.isDeviceAuthorized(
        privateKeyToAccount(DEVICE_C_KEY).address
      ),
    },
    guardians: await recovery.getGuardians(),
    quorum: await recovery.getQuorum(),
    timelockSeconds: await recovery.getTimelockSeconds(),
    status: await recovery.getStatus(),
    activeRequest: request
      ? {
          recoveryId: request.recoveryId.toString(),
          initiator: request.initiator,
          replacedDevice: request.replacedDevice,
          newDevice: request.newDevice,
          approvals: request.approvals,
          quorumSnapshot: request.quorumSnapshot,
          executeAfter: request.executeAfter?.toString() ?? null,
          status: request.status,
        }
      : null,
    chainNow: block.timestamp.toString(),
  };
}

export async function GET() {
  try {
    const stack = await getStack();
    return NextResponse.json(await buildState(stack));
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
}

const ACTIONS = new Set(['initiate', 'approve', 'cancel', 'finalize', 'reset']);

export async function POST(request: Request) {
  let action = '';
  try {
    const body = (await request.json()) as { action?: string };
    action = body.action ?? '';
    if (!ACTIONS.has(action)) {
      return fail(`unknown action: ${action || '(none)'}`);
    }
    if (!(await nodeReachable())) {
      return fail(`no Ethereum node at ${RPC_URL}. Start one with \`anvil\`, then retry.`);
    }

    const stack = await getStack();
    const recovery = recoverySession(stack);
    const guardian1 = privateKeyToAccount(GUARDIAN_1_KEY);
    const deviceB = privateKeyToAccount(DEVICE_B_KEY);

    let detail = '';
    switch (action) {
      case 'reset': {
        cachedStack = null;
        detail = 'demo stack discarded; a fresh wallet deploys on next refresh';
        break;
      }
      case 'initiate': {
        await recovery.initiate({
          account: deviceB,
          replacedDevice: privateKeyToAccount(DEVICE_A_KEY).address,
          newDevice: privateKeyToAccount(DEVICE_C_KEY).address,
        });
        detail = `recovery opened by healthy device ${deviceB.address.slice(0, 8)}…`;
        break;
      }
      case 'approve': {
        await recovery.approve(guardian1);
        detail = `guardian ${guardian1.address.slice(0, 8)}… approved`;
        break;
      }
      case 'cancel': {
        await recovery.cancel(deviceB); // authorized devices may cancel
        detail = `recovery cancelled by device ${deviceB.address.slice(0, 8)}…`;
        break;
      }
      case 'finalize': {
        await recovery.finalize(privateKeyToAccount(MANAGER_KEY)); // permissionless relay
        detail = 'timelock elapsed; recovery executed atomically';
        break;
      }
    }

    const state = await buildState(stack);
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
