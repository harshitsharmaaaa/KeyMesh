/**
 * End-to-end Phase 1.1 integration against a local Anvil node.
 *
 * Covers: start Anvil -> forge build -> deploy KeymeshWallet -> device
 * registration -> create/sign/execute -> recipient state, nonce, event ->
 * replay rejection -> revocation -> unauthorized signer rejection.
 *
 * Usage: bun run integration:anvil
 * Uses only PUBLIC deterministic Anvil fixture keys (local test network).
 */
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import {
  http,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  formatEther,
} from 'viem';
import type { PublicClient } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import {
  type buildKeymeshTransaction,
  canonicalTransactionHex,
  createKeymeshSession,
  deployKeymeshWallet,
  keymeshWalletAbi,
} from '../src/index';

const PORT = process.env.KEYMESH_ANVIL_PORT ?? '8545';
const RPC_URL = `http://127.0.0.1:${PORT}`;
const REPO_ROOT = path.resolve(import.meta.dir, '..', '..', '..');
const CONTRACTS_DIR = path.join(REPO_ROOT, 'contracts', 'ethereum');
const ARTIFACT_PATH = path.join(CONTRACTS_DIR, 'out', 'KeymeshWallet.sol', 'KeymeshWallet.json');

/** Well-known PUBLIC Anvil mnemonic accounts (test networks only). */
const MANAGER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const DEVICE_A_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const DEVICE_B_KEY = '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e' as const;

class StepFailure extends Error {}

function requireStep(condition: boolean, detail: string): void {
  if (!condition) throw new StepFailure(detail);
}

function log(step: string, detail: string): void {
  console.log(`[ok] ${step}: ${detail}`);
}

async function findBinary(name: 'anvil' | 'forge'): Promise<string> {
  const exe = process.platform === 'win32' ? `${name}.exe` : name;
  const probe = spawnSync(name, ['--version'], { stdio: 'ignore' });
  if (probe.status === 0) return name;
  const local = path.join(homedir(), '.foundry', 'bin', exe);
  if (existsSync(local)) return local;
  throw new StepFailure(
    `${name} not found on PATH or in ~/.foundry/bin; install Foundry (https://book.getfoundry.sh)`
  );
}

async function waitUntilResponsive(url: string, tries = 60, delayMs = 250): Promise<void> {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
        signal: AbortSignal.timeout(1000),
      });
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new StepFailure(`Anvil did not become responsive at ${url}`);
}

function makePublicClient(): PublicClient {
  return createPublicClient({
    chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
    transport: http(RPC_URL),
  });
}

interface Artifact {
  abi: unknown[];
  bytecode: { object: `0x${string}` };
}

async function loadArtifact(): Promise<Artifact> {
  const raw = JSON.parse(await readFile(ARTIFACT_PATH, 'utf8')) as Artifact;
  if (!raw.abi || !raw.bytecode?.object) {
    throw new StepFailure(`unexpected artifact shape at ${ARTIFACT_PATH}`);
  }
  return raw;
}

function executeCalldata(
  tx: ReturnType<typeof buildKeymeshTransaction>,
  signature: `0x${string}`
): `0x${string}` {
  return encodeFunctionData({
    abi: keymeshWalletAbi,
    functionName: 'execute',
    args: [tx.wallet, tx.chainId, tx.to, tx.value, tx.data, tx.nonce, tx.expiry, signature],
  }) as `0x${string}`;
}

async function main(): Promise<void> {
  let anvil: ChildProcess | null = null;
  try {
    // 1. start Anvil
    const anvilBin = await findBinary('anvil');
    await fetch(RPC_URL, {
      method: 'POST',
      body: '{}',
      signal: AbortSignal.timeout(400),
    }).then(
      () => {
        throw new StepFailure(
          `${RPC_URL} already serves a node; free the port or set KEYMESH_ANVIL_PORT`
        );
      },
      () => undefined
    );
    anvil = spawn(anvilBin, ['--port', PORT, '--block-time', '1'], { stdio: 'ignore' });
    anvil.on('exit', (code) => {
      if (code !== null && code !== 0) throw new StepFailure(`anvil exited early (${code})`);
    });
    await waitUntilResponsive(RPC_URL);
    log('anvil', `listening on ${RPC_URL} (chain ${foundry.id})`);

    const forgeBin = await findBinary('forge');
    const build = spawnSync(forgeBin, ['build', '--root', CONTRACTS_DIR], { stdio: 'ignore' });
    requireStep(build.status === 0, `forge build failed (status ${build.status})`);
    const artifact = await loadArtifact();

    const manager = privateKeyToAccount(MANAGER_KEY);
    const deviceA = privateKeyToAccount(DEVICE_A_KEY);
    const deviceB = privateKeyToAccount(DEVICE_B_KEY);
    const strangerKey = generatePrivateKey();

    // 2. deploy KeymeshWallet
    const deployed = await deployKeymeshWallet({
      artifactAbi: artifact.abi,
      artifactBytecode: artifact.bytecode.object,
      rpcUrl: RPC_URL,
      chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
      managerAccount: manager,
      initialDevice: deviceA.address,
    });
    log('deploy', `KeymeshWallet at ${deployed.address}`);

    const client = makePublicClient();
    const deviceSession = createKeymeshSession({
      walletAddress: deployed.address,
      chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_A_KEY,
      relayerAccount: manager,
      managerAccount: manager,
    });

    // 3. devices: initial device authorized at construction, second registered
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceA.address)) === true,
      'initial device should be authorized'
    );
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceB.address)) === false,
      'unregistered device must not be authorized'
    );
    await deviceSession.registerDevice(deviceB.address);
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceB.address)) === true,
      'registerDevice should authorize device B'
    );
    log('devices', `registered device B (${deviceB.address})`);

    // fund the wallet so it can pay transfers
    const relayer = createWalletClient({
      account: manager,
      chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
      transport: http(RPC_URL),
    });
    const fundingHash = await relayer.sendTransaction({
      to: deployed.address,
      value: 10n ** 18n,
    });
    await client.waitForTransactionReceipt({ hash: fundingHash });

    // 4-6. construct, sign, submit
    const nonceBefore = await deviceSession.getNonce();
    const request = await deviceSession.createTransaction({
      to: deviceB.address,
      value: 10n ** 17n, // 0.1 ETH
    });
    const signed = deviceSession.signTransaction(request);
    log(
      'sign',
      `digest ${signed.digest} (canonical ${canonicalTransactionHex(request).slice(0, 18)}...)`
    );

    // 7-10. execute + verify contract execution, recipient state, nonce, event
    const result = await deviceSession.execute(signed);
    const nonceAfter = await deviceSession.getNonce();
    const recipientBalance = await client.getBalance({ address: deviceB.address });

    requireStep(result.status === 'success', 'execution receipt should be success');
    requireStep(result.device === deviceA.address, 'event signer should be device A');
    requireStep(
      result.to === deviceB.address && result.value === 10n ** 17n,
      'event fields should echo the request'
    );
    requireStep(
      nonceAfter === nonceBefore + 1n,
      `nonce should increment (${nonceBefore} -> ${nonceAfter})`
    );
    log('execute', `tx ${result.txHash}`);
    log('state', `recipient balance ${formatEther(recipientBalance)} ETH, nonce ${nonceAfter}`);

    // replay protection: the same signed payload must now be rejected
    let replayRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: deployed.address,
        data: executeCalldata(signed.transaction, signed.signature),
      });
    } catch (err) {
      replayRejected = true;
      log('replay', `rejected as expected (${shortReason(err)})`);
    }
    requireStep(replayRejected, 'replayed transaction must be rejected');

    // unauthorized signer
    const strangerSession = createKeymeshSession({
      walletAddress: deployed.address,
      chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
      rpcUrl: RPC_URL,
      devicePrivateKey: strangerKey,
    });
    const strangerRequest = await strangerSession.createTransaction({
      to: deviceA.address,
      value: 0n,
    });
    const strangerSigned = strangerSession.signTransaction(strangerRequest);
    let unauthorizedRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: deployed.address,
        data: executeCalldata(
          deployed.address,
          strangerSigned.transaction,
          strangerSigned.signature
        ),
      });
    } catch (err) {
      unauthorizedRejected = true;
      log('authorization', `stranger signature rejected (${shortReason(err)})`);
    }
    requireStep(unauthorizedRejected, 'unauthorized device signature must be rejected');

    // revocation removes authority immediately
    await deviceSession.revokeDevice(deviceB.address);
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceB.address)) === false,
      'revoked device must lose authorization'
    );
    const revokedSession = createKeymeshSession({
      walletAddress: deployed.address,
      chain: { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } },
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_B_KEY,
    });
    const revokedRequest = await revokedSession.createTransaction({
      to: deviceA.address,
      value: 0n,
    });
    const revokedSigned = revokedSession.signTransaction(revokedRequest);
    let revokedRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: deployed.address,
        data: executeCalldata(revokedSigned.transaction, revokedSigned.signature),
      });
    } catch (err) {
      revokedRejected = true;
      log('revocation', `revoked-device signature rejected (${shortReason(err)})`);
    }
    requireStep(revokedRejected, 'revoked device signature must be rejected');

    console.log(
      '\nINTEGRATION PASS: full SDK -> signature -> Solidity verification -> execution flow verified on Anvil.'
    );
  } finally {
    anvil?.kill();
  }
}

main().catch((err: unknown) => {
  if (err instanceof StepFailure) {
    console.error(`\nINTEGRATION FAIL: ${err.message}`);
  } else {
    console.error('\nINTEGRATION FAIL:', err);
  }
  process.exitCode = 1;
});

function shortReason(err: unknown): string {
  const text = String(
    (err as { shortMessage?: string; message?: string })?.shortMessage ??
      (err as { message?: string })?.message ??
      err
  );
  return text.length > 140 ? `${text.slice(0, 137)}...` : text.replace(/\s+/g, ' ');
}
