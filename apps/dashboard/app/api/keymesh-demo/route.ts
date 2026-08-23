import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { type ExecutionResult, createKeymeshSession, deployKeymeshWallet } from '@keymesh/sdk';
import { NextResponse } from 'next/server';
import { http, createPublicClient, createWalletClient, formatEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

export const dynamic = 'force-dynamic';

/**
 * Phase 1.1 demo endpoint: runs a real device-signed transaction through the
 * SDK against a LOCAL Anvil node. Runs entirely server-side.
 *
 * Keys below are PUBLIC deterministic Anvil fixture keys (test networks only).
 * They never leave this module — the browser only receives addresses and
 * hashes. No production key custody exists in this phase.
 */
const MANAGER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const DEVICE_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const RECIPIENT = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' as const;

const RPC_URL = process.env.KEYMESH_DEMO_RPC_URL ?? 'http://127.0.0.1:8545';
const chain = { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } };

interface DemoStep {
  name: string;
  detail: string;
}

function fail(error: string) {
  return NextResponse.json({ ok: false, error }, { status: 500 });
}

async function loadArtifact(): Promise<{ abi: unknown[]; bytecodeObject: `0x${string}` }> {
  const artifactPath = path.resolve(
    process.cwd(),
    '..',
    '..',
    'contracts',
    'ethereum',
    'out',
    'KeymeshWallet.sol',
    'KeymeshWallet.json'
  );
  let raw: string;
  try {
    raw = await readFile(artifactPath, 'utf8');
  } catch {
    throw new Error(
      'Foundry artifact not found. Run `forge build --root contracts/ethereum` first.'
    );
  }
  const parsed = JSON.parse(raw) as {
    abi?: unknown[];
    bytecode?: { object?: `0x${string}` };
  };
  if (!parsed.abi?.length || !parsed.bytecode?.object) {
    throw new Error(`Unexpected artifact shape at ${artifactPath}`);
  }
  return { abi: parsed.abi, bytecodeObject: parsed.bytecode.object };
}

export async function POST() {
  const steps: DemoStep[] = [];
  try {
    try {
      await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
        signal: AbortSignal.timeout(1500),
      });
      steps.push({ name: 'anvil', detail: `node reachable at ${RPC_URL}` });
    } catch {
      return fail(`no Ethereum node at ${RPC_URL}. Start one with \`anvil\`, then retry.`);
    }

    const { abi, bytecodeObject } = await loadArtifact();
    const manager = privateKeyToAccount(MANAGER_KEY);
    const device = privateKeyToAccount(DEVICE_KEY);

    const deployed = await deployKeymeshWallet({
      artifactAbi: abi,
      artifactBytecode: bytecodeObject,
      rpcUrl: RPC_URL,
      chain,
      managerAccount: manager,
      initialDevice: device.address,
    });
    steps.push({
      name: 'deploy',
      detail: `KeymeshWallet at ${deployed.address} (device ${device.address} pre-authorized)`,
    });

    const publicClient = createPublicClient({ chain, transport: http(RPC_URL) });
    const relayer = createWalletClient({ account: manager, chain, transport: http(RPC_URL) });
    const fundingHash = await relayer.sendTransaction({
      to: deployed.address,
      value: 10n ** 18n,
    });
    await publicClient.waitForTransactionReceipt({ hash: fundingHash });
    steps.push({ name: 'fund', detail: 'wallet funded with 1.0 ETH' });

    // The SDK session performs create -> sign -> execute end to end.
    const session = createKeymeshSession({
      walletAddress: deployed.address,
      chain,
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_KEY,
      relayerAccount: manager,
    });

    if (!(await session.isDeviceAuthorized(device.address))) {
      throw new Error(`device ${device.address} is not authorized on the wallet contract`);
    }

    const nonceBefore = await session.getNonce();
    const request = await session.createTransaction({
      to: RECIPIENT,
      value: 10n ** 16n, // 0.01 ETH
    });
    steps.push({
      name: 'create',
      detail: `nonce ${request.nonce}, expiry ${request.expiry}, to ${request.to}`,
    });

    const signed = session.signTransaction(request);
    steps.push({ name: 'sign', detail: `digest ${signed.digest}` });

    const result: ExecutionResult = await session.execute(signed);
    const nonceAfter = await session.getNonce();
    const balanceAfter = await publicClient.getBalance({ address: RECIPIENT });
    steps.push({ name: 'execute', detail: `tx ${result.txHash} (status ${result.status})` });
    steps.push({
      name: 'verify',
      detail: `recipient balance ${formatEther(balanceAfter)} ETH; nonce ${nonceBefore} -> ${nonceAfter}; TransactionExecuted event decoded`,
    });

    return NextResponse.json({ ok: true, wallet: deployed.address, steps });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return fail(message);
  }
}
