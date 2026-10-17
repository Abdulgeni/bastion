import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createRandomSource, type RandomSource } from '../libs/bastion-common/src/random/random-source';
import { SystemClock } from '../libs/bastion-common/src/clock/clock';
import { ensureJwtKeyRing } from './rotate-jwt';
import { readCliOptions } from './pki/cli-options';
import { readCliOptions as _unused } from './pki/cli-options';
void _unused;

export interface InitResult {
  readonly varDir: string;
  readonly created: readonly string[];
  readonly kept: readonly string[];
}

/** Write a file if it does not already exist, with the given mode. Returns true if created. */
function writeOnce(path: string, contents: string | Buffer, mode: number): boolean {
  if (existsSync(path)) return false;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, { mode });
  chmodSync(path, mode);
  return true;
}

/** A random 32-byte hex string. */
function randomHex(random: RandomSource): string {
  return random.bytes(32).toString('hex');
}

/** The Vault AppRole policy. F4 from Step 1: `update`, not `read`, on sys/tools/random. */
const VAULT_POLICY = `# Bastion payments policy. \`sys/tools/random\` is a POST endpoint, so it needs
# \`update\` (not \`read\`) — see F4 in Step 1's design review.
path "sys/tools/random" {
  capabilities = ["update"]
}
path "sys/tools/random/*" {
  capabilities = ["update"]
}
`;

/**
 * Phase A of the two-phase bootstrap. Generates the Vault root token, the AppRole
 * credentials, the policy file, and the demo credentials file. Idempotent: files
 * that already exist are left alone (this is what `compose up` calls every time).
 *
 * The AppRole `role_id` and `wrapped_secret_id` are placeholders here — the actual
 * values are minted by Vault and written by `vault-bootstrap.sh` (phase B). This
 * script only creates the files if Vault is not yet bootstrapped, so the init
 * container can start Vault with a known root token on a fresh run.
 */
export function initMaterial(varDir: string): InitResult {
  const random = createRandomSource({ nodeEnv: 'production' });
  const created: string[] = [];
  const kept: string[] = [];

  const files: ReadonlyArray<readonly [string, () => string | Buffer, number]> = [
    // Vault root token: Vault dev mode reads this at start.
    [join(varDir, 'vault', 'root-token'), () => randomHex(random), 0o600],
    // Policy the payments role will use. Only created once; harmless if Vault
    // is re-bootstrapped against an existing file.
    [join(varDir, 'vault', 'policy.hcl'), () => VAULT_POLICY, 0o644],
    // Demo user credentials. Only edge reads this file for its user list, and
    // even then Step 7 will hash and copy only what it needs.
    [
      join(varDir, 'demo', 'credentials.json'),
      () =>
        `${JSON.stringify(
          {
            users: [
              { sub: 'alice', password: 'hunter2' },
              { sub: 'bob', password: 'hunter3' },
            ],
          },
          null,
          2,
        )}\n`,
      0o600,
    ],
  ];

  for (const [path, make, mode] of files) {
    if (writeOnce(path, make(), mode)) created.push(path);
    else kept.push(path);
  }

  // JWT signing key ring for edge. Uses the same rotation helper `rotate-jwt`
  // uses, so the file layout is identical to what a manual rotation produces.
  const jwtKeysDir = join(varDir, 'jwt');
  if (!existsSync(join(jwtKeysDir, 'current'))) {
    ensureJwtKeyRing({ varDir, random, clock: new SystemClock() });
    created.push(join(jwtKeysDir, 'current'));
  } else {
    kept.push(join(jwtKeysDir, 'current'));
  }

  return { varDir, created, kept };
}

/** Reads the root token from disk. Throws if it is missing. */
export function readRootToken(varDir: string): string {
  const path = join(varDir, 'vault', 'root-token');
  if (!existsSync(path)) throw new Error(`no Vault root token at ${path}; run init.ts first`);
  // Use a small read; do not import fs/promises just for this.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require('node:fs') as typeof import('node:fs');
  return fs.readFileSync(path, 'utf8').trim();
}

function main(): void {
  const opts = readCliOptions(process.env, process.argv.slice(2));
  const result = initMaterial(opts.varDir);
  process.stdout.write(`var dir: ${result.varDir}\n`);
  process.stdout.write(`created: ${result.created.length === 0 ? '(none)' : result.created.join(', ')}\n`);
  process.stdout.write(`kept:    ${result.kept.length === 0 ? '(none)' : result.kept.join(', ')}\n`);
}

if (require.main === module) main();
