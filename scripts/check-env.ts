#!/usr/bin/env bun
/**
 * Environment sanity check: verifies required toolchains are available.
 * Run with: bun scripts/check-env.ts
 */

const checks: Array<{ name: string; cmd: string[]; optional: boolean }> = [
  { name: 'bun', cmd: ['bun', '--version'], optional: false },
  { name: 'cargo', cmd: ['cargo', '--version'], optional: true },
  { name: 'forge', cmd: ['forge', '--version'], optional: true },
];

let missing = 0;

for (const check of checks) {
  try {
    const proc = Bun.spawnSync(check.cmd, { stdout: 'pipe', stderr: 'pipe' });
    const version = proc.stdout.toString().trim();
    if (proc.exitCode === 0 && version) {
      console.log(`[ok] ${check.name}: ${version.split('\n')[0]}`);
    } else {
      throw new Error('non-zero exit');
    }
  } catch {
    missing++;
    const label = check.optional ? 'optional' : 'REQUIRED';
    console.error(`[missing] ${check.name} (${label})`);
  }
}

console.log('');
console.log(
  missing === 0
    ? 'All toolchains available.'
    : `${missing} toolchain(s) unavailable — see docs/development/local-development.md`
);
