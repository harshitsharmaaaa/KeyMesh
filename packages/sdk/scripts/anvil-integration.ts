/**
 * End-to-end Phase 1.1 + 1.2 integration against a local Anvil node.
 *
 * Phase 1.1: deploy -> device-signed canonical transaction -> execution,
 *            nonce/replay/revocation checks.
 * Phase 1.2: guardian bootstrap -> recovery request -> guardian quorum ->
 *            timelock (early finalization rejected, time advanced) ->
 *            finalization -> new device authorized / stolen device revoked ->
 *            new-device signing works on-chain, old-device rejected ->
 *            finalized recovery cannot be replayed.
 *
 * Usage: bun run integration:anvil
 * Uses only PUBLIC deterministic Anvil fixture keys (local test network).
 */
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { type KeymeshTransaction, hashKeymeshTransaction } from '@keymesh/protocol';
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
  createKeymeshPolicySession,
  createKeymeshRecoverySession,
  createKeymeshSession,
  deployKeymeshStack,
  keymeshWalletAbi,
} from '../src/index';

const PORT = process.env.KEYMESH_ANVIL_PORT ?? '8545';
const RPC_URL = `http://127.0.0.1:${PORT}`;
const REPO_ROOT = path.resolve(import.meta.dir, '..', '..', '..');
const CONTRACTS_DIR = path.join(REPO_ROOT, 'contracts', 'ethereum');
const OUT_DIR = path.join(CONTRACTS_DIR, 'out');

/** Well-known PUBLIC Anvil mnemonic accounts (test networks only). */
const MANAGER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const DEVICE_A_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;
const DEVICE_B_KEY = '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e' as const;
// Anvil fixture accounts #3 and #4: recovery target device + first guardian.
const DEVICE_C_KEY = '0x90c0a13f8d60af5fedfea56a44457ee5f8ad8ddf10b78acfe023a4cc75be54a3' as const;
const GUARDIAN_1_KEY =
  '0x7660cb9dd74b356c67c855a3708d0dab24ef522c80d9ade7e7a476d7d543aeae' as const;
// Deterministic local-only keys for the remaining guardians.
const GUARDIAN_2_KEY =
  '0x1111111111111111111111111111111111111111111111111111111111111111' as const;
const GUARDIAN_3_KEY =
  '0x2222222222222222222222222222222222222222222222222222222222222222' as const;

const TIMELOCK_SECONDS = 3600; // protocol minimum; short enough for local tests

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

async function rpcCall(method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(5000),
  });
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  if (body.error) throw new StepFailure(`rpc ${method} failed: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function chainNow(client: PublicClient): Promise<bigint> {
  const block = await client.getBlock({ blockTag: 'latest' });
  return block.timestamp;
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

async function loadArtifact(name: string): Promise<Artifact> {
  const artifactPath = path.join(OUT_DIR, `${name}.sol`, `${name}.json`);
  const raw = JSON.parse(await readFile(artifactPath, 'utf8')) as Artifact;
  if (!raw.abi || !raw.bytecode?.object) {
    throw new StepFailure(`unexpected artifact shape at ${artifactPath}`);
  }
  return raw;
}

function executeCalldata(tx: KeymeshTransaction, signature: `0x${string}`): `0x${string}` {
  return encodeFunctionData({
    abi: keymeshWalletAbi,
    functionName: 'execute',
    args: [tx.wallet, tx.chainId, tx.to, tx.value, tx.data, tx.nonce, tx.expiry, signature],
  }) as `0x${string}`;
}

async function main(): Promise<void> {
  let anvil: ChildProcess | null = null;
  try {
    // ---------------------------------------------------------------
    // 1. start Anvil
    // ---------------------------------------------------------------
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
    await waitUntilResponsive(RPC_URL);
    log('anvil', `listening on ${RPC_URL} (chain ${foundry.id})`);

    const forgeBin = await findBinary('forge');
    const build = spawnSync(forgeBin, ['build', '--root', CONTRACTS_DIR], { stdio: 'ignore' });
    requireStep(build.status === 0, `forge build failed (status ${build.status})`);
    const walletArtifact = await loadArtifact('KeymeshWallet');
    const recoveryArtifact = await loadArtifact('RecoveryManager');
    const policyArtifact = await loadArtifact('PolicyManager');

    const manager = privateKeyToAccount(MANAGER_KEY);
    const deviceA = privateKeyToAccount(DEVICE_A_KEY); // initial device ("stolen" later)
    const deviceB = privateKeyToAccount(DEVICE_B_KEY); // healthy co-owned device
    const deviceC = privateKeyToAccount(DEVICE_C_KEY); // replacement device
    const guardian1 = privateKeyToAccount(GUARDIAN_1_KEY);
    const guardian2 = privateKeyToAccount(GUARDIAN_2_KEY);
    const guardian3 = privateKeyToAccount(GUARDIAN_3_KEY);

    const client = makePublicClient();
    const chain = { ...foundry, rpcUrls: { default: { http: [RPC_URL] } } };

    // ---------------------------------------------------------------
    // 2-3. deploy contracts + wallet (initial device pre-authorized)
    // ---------------------------------------------------------------
    const stack = await deployKeymeshStack({
      rpcUrl: RPC_URL,
      chain,
      walletArtifact: { abi: walletArtifact.abi, bytecode: walletArtifact.bytecode.object },
      recoveryArtifact: { abi: recoveryArtifact.abi, bytecode: recoveryArtifact.bytecode.object },
      policyArtifact: { abi: policyArtifact.abi, bytecode: policyArtifact.bytecode.object },
      managerAccount: manager,
      initialDevice: deviceA.address,
    });
    log(
      'deploy',
      `wallet ${stack.walletAddress}, recovery ${stack.recoveryAddress}, policy ${String(stack.policyAddress)}, registry ${stack.registryAddress}`
    );
    requireStep(stack.policyAddress !== null, 'policy layer must be wired');
    log(
      'deploy',
      `KeymeshWallet ${stack.walletAddress}, RecoveryManager ${stack.recoveryAddress}, GuardianRegistry ${stack.registryAddress}`
    );
    requireStep(
      (await createKeymeshSession({
        walletAddress: stack.walletAddress,
        chain,
        rpcUrl: RPC_URL,
        devicePrivateKey: DEVICE_A_KEY,
      }).isDeviceAuthorized(deviceA.address)) === true,
      'initial device should be authorized'
    );

    const deviceSession = createKeymeshSession({
      walletAddress: stack.walletAddress,
      chain,
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_A_KEY,
      relayerAccount: manager,
      managerAccount: manager,
    });

    // Multi-device wallets are supported: register a second device BEFORE
    // bootstrap (the manager loses registration power afterwards).
    await deviceSession.registerDevice(deviceB.address);
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceB.address)) === true,
      'registerDevice should authorize device B'
    );

    // Fund the wallet so it can pay transfers, and fund every account that
    // must pay gas (guardians, replacement device). Deterministic local
    // accounts only; never real funds.
    const relayer = createWalletClient({
      account: manager,
      chain,
      transport: http(RPC_URL),
    });
    const fundingHash = await relayer.sendTransaction({
      to: stack.walletAddress,
      value: 10n ** 18n,
    });
    await client.waitForTransactionReceipt({ hash: fundingHash });
    for (const funded of [guardian1, guardian2, guardian3, deviceC]) {
      const hash = await relayer.sendTransaction({ to: funded.address, value: 10n ** 17n });
      await client.waitForTransactionReceipt({ hash });
    }

    // ---------------------------------------------------------------
    // Phase 1.1 regression: device-signed transaction end-to-end
    // ---------------------------------------------------------------
    const request = await deviceSession.createTransaction({
      to: deviceB.address,
      value: 10n ** 17n,
      nowSeconds: await chainNow(client),
    });
    const signed = deviceSession.signTransaction(request);
    const result = await deviceSession.execute(signed);
    requireStep(result.status === 'success', 'phase 1.1 execution receipt should be success');
    log('execute', `device A tx ${result.txHash}`);

    let replayRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: stack.walletAddress,
        data: executeCalldata(signed.transaction, signed.signature),
      });
    } catch (err) {
      replayRejected = true;
      log('replay', `rejected as expected (${shortReason(err)})`);
    }
    requireStep(replayRejected, 'replayed transaction must be rejected');

    // ---------------------------------------------------------------
    // 3-4. bootstrap guardians + verify guardian set
    // ---------------------------------------------------------------
    const recovery = createKeymeshRecoverySession({
      walletAddress: stack.walletAddress,
      recoveryAddress: stack.recoveryAddress,
      registryAddress: stack.registryAddress,
      chain,
      rpcUrl: RPC_URL,
    });

    await recovery.bootstrap({
      managerAccount: manager,
      initialGuardians: [guardian1.address, guardian2.address, guardian3.address],
      quorum: 2,
      timelockSeconds: TIMELOCK_SECONDS,
    });
    const guardians = await recovery.getGuardians();
    requireStep(guardians.length === 3, 'bootstrap should register three guardians');
    requireStep(
      guardians.includes(guardian1.address) &&
        guardians.includes(guardian2.address) &&
        guardians.includes(guardian3.address),
      'registered guardian set mismatch'
    );
    requireStep((await recovery.getQuorum()) === 2, 'quorum should be 2');
    requireStep((await recovery.getStatus()) === 'none', 'status should be none after bootstrap');
    log('bootstrap', `guardians [${guardians.map((g) => g.slice(0, 8)).join(', ')}] quorum=2`);

    // Manager authority is now retired.
    let managerRetired = false;
    try {
      await deviceSession.registerDevice(guardian3.address);
    } catch (err) {
      managerRetired = true;
      log('authority', `manager registration rejected post-bootstrap (${shortReason(err)})`);
    }
    requireStep(managerRetired, 'manager must not register devices after initialization');
    requireStep(
      (await recovery.minTimelockSeconds()) === 3600,
      'protocol minimum timelock should be 1 hour'
    );

    // ---------------------------------------------------------------
    // 5. initiate recovery (replacing "stolen" device A with device C)
    // ---------------------------------------------------------------
    await recovery.initiate({
      account: deviceB, // any authorized device may initiate
      replacedDevice: deviceA.address,
      newDevice: deviceC.address,
    });
    const activeRequest = await recovery.getActiveRequest();
    requireStep(activeRequest !== null, 'active recovery request should exist');
    const opened = activeRequest as NonNullable<typeof activeRequest>;
    requireStep(opened.status === 'pending', 'request should start pending');
    requireStep(
      opened.newDevice === deviceC.address && opened.replacedDevice === deviceA.address,
      'request should name the device swap'
    );
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceC.address)) === false,
      'creating a request must NOT authorize the new device'
    );
    log('initiate', `recovery #${opened.recoveryId}: deviceA -> deviceC`);

    // Unauthorized initiator must be rejected.
    let initiateRejected = false;
    try {
      await recovery.approve(privateKeyToAccount(generatePrivateKey())); // non-guardian
    } catch (err) {
      initiateRejected = true;
      log('approval', `non-guardian approval rejected (${shortReason(err)})`);
    }
    requireStep(initiateRejected, 'non-guardian approval must be rejected');

    // ---------------------------------------------------------------
    // 6-7. guardian approvals
    // ---------------------------------------------------------------
    await recovery.approve(guardian1);
    const afterFirst = (await recovery.getActiveRequest()) ?? null;
    requireStep(afterFirst?.approvals === 1, 'one approval should be recorded');
    requireStep((await recovery.getStatus()) === 'pending', 'below quorum stays pending');
    log('approve', 'guardian 1 approved (1/2)');

    let duplicateRejected = false;
    try {
      await recovery.approve(guardian1); // double approval
    } catch (err) {
      duplicateRejected = true;
      log('approval', `duplicate approval rejected (${shortReason(err)})`);
    }
    requireStep(duplicateRejected, 'duplicate approval must be rejected');

    await recovery.approve(guardian2);
    log('approve', 'guardian 2 approved (2/2)');

    // ---------------------------------------------------------------
    // 8. verify quorum reached (timelock armed)
    // ---------------------------------------------------------------
    const afterQuorum = await recovery.getActiveRequest();
    requireStep(afterQuorum !== null, 'request still active after quorum');
    const reached = afterQuorum as NonNullable<typeof afterQuorum>;
    requireStep(reached.status === 'quorum_reached', 'quorum should transition status');
    requireStep(reached.approvals === 2, 'two approvals recorded');
    requireStep(
      reached.executeAfter !== null && reached.executeAfter > 0n,
      'timelock deadline should be set'
    );
    const executeAfter = reached.executeAfter as bigint;
    log('quorum', `reached; executeAfter=${executeAfter}`);

    // ---------------------------------------------------------------
    // 9. verify timelock prevents early finalization
    // ---------------------------------------------------------------
    let earlyFinalizeRejected = false;
    try {
      await recovery.finalize(manager);
    } catch (err) {
      earlyFinalizeRejected = true;
      log('timelock', `early finalization rejected (${shortReason(err)})`);
    }
    requireStep(earlyFinalizeRejected, 'finalization before executeAfter must revert');
    requireStep(
      (await deviceSession.isDeviceAuthorized(deviceC.address)) === false,
      'early finalization attempt must not change devices'
    );

    // ---------------------------------------------------------------
    // 10. advance Anvil time past the timelock
    // ---------------------------------------------------------------
    const now = await chainNow(client);
    const delta = Number(executeAfter - now) + 1;
    await rpcCall('evm_increaseTime', [Math.max(delta, 1)]);
    await rpcCall('evm_mine', []);
    requireStep(
      (await recovery.getStatus()) === 'executable',
      'status should be executable once the timelock elapsed'
    );
    log('timelock', `advanced ${delta}s; recovery is executable`);

    // ---------------------------------------------------------------
    // 11. finalize recovery
    // ---------------------------------------------------------------
    await recovery.finalize(manager);
    requireStep(
      (await recovery.getStatus()) === 'executed',
      'status should be executed after finalization'
    );

    // ---------------------------------------------------------------
    // 12-13. verify device set: C authorized, A revoked
    // ---------------------------------------------------------------
    requireStep(
      (await recovery.isDeviceAuthorized(deviceC.address)) === true,
      'replacement device must be authorized after recovery'
    );
    requireStep(
      (await recovery.isDeviceAuthorized(deviceA.address)) === false,
      'stolen device must be revoked after recovery'
    );
    requireStep(
      (await recovery.isDeviceAuthorized(deviceB.address)) === true,
      'unrelated device must be untouched'
    );
    log('finalize', 'device C authorized, device A revoked, device B intact');

    // ---------------------------------------------------------------
    // 14-15. sign + execute with the NEW device
    // ---------------------------------------------------------------
    const newDeviceSession = createKeymeshSession({
      walletAddress: stack.walletAddress,
      chain,
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_C_KEY,
      relayerAccount: manager,
    });
    const newRequest = await newDeviceSession.createTransaction({
      to: deviceC.address,
      value: 10n ** 16n,
      nowSeconds: await chainNow(client),
    });
    const newSigned = newDeviceSession.signTransaction(newRequest);
    const newResult = await newDeviceSession.execute(newSigned);
    requireStep(newResult.status === 'success', 'new-device transaction must succeed');
    requireStep(newResult.device === deviceC.address, 'event signer should be device C');
    log('execute', `new device tx ${newResult.txHash} (${formatEther(newResult.value)} ETH)`);

    // ---------------------------------------------------------------
    // 16-17. old device signature rejected
    // ---------------------------------------------------------------
    const staleSession = createKeymeshSession({
      walletAddress: stack.walletAddress,
      chain,
      rpcUrl: RPC_URL,
      devicePrivateKey: DEVICE_A_KEY,
    });
    const staleRequest = await staleSession.createTransaction({
      to: deviceB.address,
      value: 0n,
      nowSeconds: await chainNow(client),
    });
    const staleSigned = staleSession.signTransaction(staleRequest);
    let oldDeviceRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: stack.walletAddress,
        data: executeCalldata(staleSigned.transaction, staleSigned.signature),
      });
    } catch (err) {
      oldDeviceRejected = true;
      log('revocation', `old-device signature rejected (${shortReason(err)})`);
    }
    requireStep(oldDeviceRejected, 'revoked device signature must be rejected');

    // ---------------------------------------------------------------
    // 18. recovery cannot be replayed
    // ---------------------------------------------------------------
    let finalizeReplayRejected = false;
    try {
      await recovery.finalize(manager);
    } catch (err) {
      finalizeReplayRejected = true;
      log('no-replay', `second finalization rejected (${shortReason(err)})`);
    }
    requireStep(finalizeReplayRejected, 'executed recovery must never execute again');

    // ===============================================================
    // Phase 1.3: transaction authorization policies
    // ===============================================================
    requireStep(stack.policyAddress !== null, 'policy address required');
    const policySession = createKeymeshPolicySession({
      walletAddress: stack.walletAddress,
      policyAddress: stack.policyAddress as Address,
      chain,
      rpcUrl: RPC_URL,
      governanceDevicePrivateKey: DEVICE_C_KEY,
      relayerAccount: manager,
    });

    // 1. create normal policy through governed administration (structural
    //    anti-downgrade rule: admin calls need guardian authorization).
    //    Bootstrap semantics: the wallet's policy is still unconfigured, so
    //    the request quorum clamps to ONE guardian for this first change;
    //    afterwards the configured quorum (2) applies to all further changes.
    const configureInput = {
      defaultMode: 'device_only' as const,
      valueThresholdWei: '500000000000000000', // 0.5 ETH
      guardianApprovalsRequired: 2,
    };
    let changeDigest: `0x${string}`;
    const configureProposal = await policySession.proposeConfigurePolicy(configureInput);
    changeDigest = configureProposal.digest;
    await policySession.approveTransaction(guardian1, changeDigest);
    await policySession.executeConfigurePolicy(configureInput, configureProposal);

    // 14 (partial). verify policy version behavior
    let cfg = await policySession.getPolicyConfig();
    requireStep(cfg.version === 1, `policy version should be 1 (got ${cfg.version})`);
    requireStep(cfg.valueThresholdWei === '500000000000000000');
    log(
      'policy',
      `configured v${cfg.version}: threshold ${formatEther(BigInt(cfg.valueThresholdWei))} ETH, quorum ${cfg.guardianApprovalsRequired}`
    );

    // 2. low-value transaction executes with device signature only
    const lowBefore = await client.getBalance({ address: guardian1.address });
    const lowRequest = await newDeviceSession.createTransaction({
      to: guardian1.address,
      value: 10n ** 17n, // 0.1 ETH < threshold
      nowSeconds: await chainNow(client),
    });
    const lowResult = await newDeviceSession.execute(newDeviceSession.signTransaction(lowRequest));
    requireStep(lowResult.status === 'success', 'low-value device-only execution must succeed');
    const lowAfter = await client.getBalance({ address: guardian1.address });
    requireStep(lowAfter === lowBefore + 10n ** 17n, 'recipient state changed');
    log('execute', `device-only tx ${lowResult.txHash} (0.1 ETH)`);

    // 3-4. high-value transaction rejected without guardian authorization
    const highValue = 700000000000000000n; // 0.7 ETH > threshold
    const highRequest = await newDeviceSession.createTransaction({
      to: guardian2.address,
      value: highValue,
      nowSeconds: await chainNow(client),
    });
    const highSigned = newDeviceSession.signTransaction(highRequest);
    let deviceOnlyRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: stack.walletAddress,
        data: executeCalldata(highSigned.transaction, highSigned.signature),
      });
    } catch (err) {
      deviceOnlyRejected = true;
      log('policy', `high-value without approval rejected (${shortReason(err)})`);
    }
    requireStep(deviceOnlyRejected, 'device-only must NOT satisfy a guardian-gated transfer');

    // 5. transaction authorization request bound to the exact digest
    await policySession.requestAuthorizationForDigest(deviceC, highSigned.digest);
    let auth = await policySession.getAuthorization(highSigned.digest);
    requireStep(auth?.status === 'pending', 'request should be pending');

    // 6-8. guardian approvals reach the quorum
    await policySession.approveTransaction(guardian1, highSigned.digest);
    await policySession.approveTransaction(guardian2, highSigned.digest);
    auth = await policySession.getAuthorization(highSigned.digest);
    requireStep(auth?.status === 'authorized' && auth.approvals === 2, 'quorum reached');
    log('authorize', `digest ${highSigned.digest.slice(0, 10)}... approved 2/2`);

    // 9-10. execute and verify state change (baseline captured right before
    // executing so the guardians' own approval gas doesn't skew the delta).
    const highBeforeExec = await client.getBalance({ address: guardian2.address });
    const exec = await newDeviceSession.execute(highSigned);
    requireStep(exec.status === 'success', 'authorized high-value execution must succeed');
    requireStep(
      (await client.getBalance({ address: guardian2.address })) === highBeforeExec + highValue,
      'state change verified'
    );
    log('execute', `guardian-approved tx ${exec.txHash} (${formatEther(highValue)} ETH)`);

    // 11-12. replay same authorization -> rejection
    let authReplayRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: stack.walletAddress,
        data: executeCalldata(highSigned.transaction, highSigned.signature),
      });
    } catch (err) {
      authReplayRejected = true;
      log('no-replay', `authorization replay rejected (${shortReason(err)})`);
    }
    requireStep(authReplayRejected, 'consumed authorization must never re-execute');

    // 13-14. governed threshold change bumps version; stale approvals die
    const newThreshold = '100000000000000000'; // 0.1 ETH
    const thresholdProposal = await policySession.proposeSetValueThreshold(newThreshold);
    changeDigest = thresholdProposal.digest;
    await policySession.approveTransaction(guardian1, changeDigest);
    await policySession.approveTransaction(guardian2, changeDigest);
    await policySession.executeSetValueThreshold(newThreshold, thresholdProposal);
    cfg = await policySession.getPolicyConfig();
    requireStep(cfg.version === 2 && cfg.valueThresholdWei === newThreshold);

    // A request created under v2 is still pending when ANOTHER governed
    // change bumps to v3: its remaining approval must then fail.
    const staleTx = await newDeviceSession.createTransaction({
      to: guardian1.address,
      value: 150000000000000000n, // 0.15 ETH > new threshold
      nowSeconds: await chainNow(client),
    });
    const staleDigest = hashKeymeshTransaction(staleTx);
    await policySession.requestAuthorizationForDigest(deviceC, staleDigest);
    await policySession.approveTransaction(guardian1, staleDigest);

    // Another governed change bumps to v3; the v2 request becomes invalid.
    const tightenProposal = await policySession.proposeSetDestinationRestriction(
      manager.address, // unrestricted destination: rule change is a no-op
      false
    );
    await policySession.approveTransaction(guardian1, tightenProposal.digest);
    await policySession.approveTransaction(guardian2, tightenProposal.digest);
    await policySession.executeSetDestinationRestriction(manager.address, false, tightenProposal);

    let staleApprovalRejected = false;
    try {
      await policySession.approveTransaction(guardian2, staleDigest);
    } catch (err) {
      staleApprovalRejected = true;
      log('versioning', `stale-request approval rejected (${shortReason(err)})`);
    }
    requireStep(staleApprovalRejected, 'policy change must invalidate stale requests');

    // New classification applies immediately: 0.02 ETH now needs guardians.
    const tiny = await newDeviceSession.createTransaction({
      to: guardian3.address,
      value: 20000000000000000n, // 0.02 ETH > 0.01 threshold
      nowSeconds: await chainNow(client),
    });
    const tinyDigest = hashKeymeshTransaction(tiny);
    await policySession.requestAuthorizationForDigest(deviceC, tinyDigest);
    await policySession.approveTransaction(guardian1, tinyDigest);
    await policySession.approveTransaction(guardian2, tinyDigest);
    const tinyExec = await newDeviceSession.execute(newDeviceSession.signTransaction(tiny));
    requireStep(tinyExec.status === 'success', 'new-threshold guarded flow executes');
    log(
      'policy',
      `new threshold active: 0.02 ETH required guardians (v${(await policySession.getPolicyConfig()).version})`
    );

    // 15. restricted destination requires stronger authorization
    const restrictedAddr = guardian3.address;
    const restrictProposal = await policySession.proposeSetDestinationRestriction(
      restrictedAddr,
      true
    );
    await policySession.approveTransaction(guardian1, restrictProposal.digest);
    await policySession.approveTransaction(guardian2, restrictProposal.digest);
    await policySession.executeSetDestinationRestriction(restrictedAddr, true, restrictProposal);
    requireStep(await policySession.isRestrictedDestination(restrictedAddr));
    requireStep(await policySession.isRestrictedDestination(restrictedAddr));

    const zeroToRestricted = await newDeviceSession.createTransaction({
      to: restrictedAddr,
      value: 0n,
      nowSeconds: await chainNow(client),
    });
    let restrictedRejected = false;
    try {
      await client.call({
        account: manager.address,
        to: stack.walletAddress,
        data: executeCalldata(zeroToRestricted.transaction, zeroToRestricted.signature),
      });
    } catch (err) {
      restrictedRejected = true;
      log('destination', `restricted destination rejected without guardians (${shortReason(err)})`);
    }
    requireStep(restrictedRejected, 'restricted destination must require guardians');

    const zeroRestrictedDigest = hashKeymeshTransaction(zeroToRestricted);
    await policySession.requestAuthorizationForDigest(deviceC, zeroRestrictedDigest);
    await policySession.approveTransaction(guardian1, zeroRestrictedDigest);
    await policySession.approveTransaction(guardian2, zeroRestrictedDigest);
    const restrictedExec = await newDeviceSession.execute(
      newDeviceSession.signTransaction(zeroToRestricted)
    );
    requireStep(restrictedExec.status === 'success', 'restricted flow executes when authorized');
    log('destination', 'restricted destination executed under full authorization');

    console.log(
      '\nINTEGRATION PASS: policies + guardian transaction authorization + recovery verified on Anvil.'
    );
  } finally {
    anvil?.kill();
  }
}

main().catch((err: unknown) => {
  const dump = (e: unknown, depth = 0): unknown => {
    if (depth > 4 || e === null || typeof e !== 'object') return e;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(e as Record<string, unknown>)) {
      if (
        [
          'message',
          'shortMessage',
          'name',
          'details',
          'raw',
          'data',
          'args',
          'version',
          'docsPath',
        ].includes(k)
      ) {
        out[k] = typeof v === 'object' && v !== null ? '[obj]' : v;
      }
    }
    if ((e as { cause?: unknown }).cause !== undefined)
      out.cause = dump((e as { cause: unknown }).cause, depth + 1);
    return out;
  };
  console.error('\nDEEP ERROR:', JSON.stringify(dump(err), null, 2).slice(0, 2500));
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
