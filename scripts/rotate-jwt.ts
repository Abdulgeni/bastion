import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateSigningKeyPem } from '../libs/bastion-common/src/jwt/key-store';
import { readCliOptions, runCli, type PkiOptions } from './pki/cli-options';

export interface RotateJwtResult {
  /** The kid now signing new tokens. */
  readonly kid: string;
  /** The kid it replaced, if there was one. */
  readonly previousKid?: string;
}

type JwtKeyOptions = Pick<PkiOptions, 'varDir' | 'random' | 'clock'>;

/** TTL of a token plus its grace window: how long a retired key stays on disk. */
const RETIREMENT_WINDOW_SECONDS = 300 + 60;

function jwtDir(varDir: string): string {
  return join(varDir, 'jwt');
}

/** Lists the `.pem` kids currently on disk, sorted ascending. */
function listKeyIds(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => n.endsWith('.pem'))
    .map((n) => n.slice(0, -'.pem'.length))
    .sort();
}

/** Reads `retired.json` (kid → retiredAtSec) if present, else an empty map. */
function readRetired(dir: string): Record<string, number> {
  const path = join(dir, 'retired.json');
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {};
    const out: Record<string, number> = {};
    for (const [kid, at] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof at === 'number' && Number.isFinite(at)) out[kid] = at;
    }
    return out;
  } catch {
    return {};
  }
}

/**
 * Generates a fresh active JWT signing key under `var/jwt/`, retires the
 * previous one, and prunes keys whose tokens can no longer be alive. Returns
 * the new kid and (if any) the previous one. Does not touch the CA.
 */
export function rotateJwtKey(opts: JwtKeyOptions): RotateJwtResult {
  const dir = jwtDir(opts.varDir);
  const previous = listKeyIds(dir).at(-1);
  const { kid, pem } = generateSigningKeyPem(opts.random);
  const nowSec = Math.floor(opts.clock.nowMs() / 1000);

  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${kid}.pem`), pem, { mode: 0o600 });

  const retired = readRetired(dir);
  const out: Record<string, number> = {};
  const cutoff = nowSec - RETIREMENT_WINDOW_SECONDS;
  for (const [oldKid, at] of Object.entries(retired)) {
    if (at > cutoff) out[oldKid] = at;
  }
  if (previous !== undefined) out[previous] = nowSec;
  writeFileSync(join(dir, 'retired.json'), `${JSON.stringify(out, null, 2)}\n`, { mode: 0o600 });

  return previous === undefined ? { kid } : { kid, previousKid: previous };
}

/** Creates the first key only if `var/jwt/` has none. Idempotent. */
export function ensureJwtKeyRing(opts: JwtKeyOptions): { created: boolean; kid: string } {
  const dir = jwtDir(opts.varDir);
  const existing = listKeyIds(dir);
  if (existing.length > 0) {
    return { created: false, kid: existing.at(-1) as string };
  }
  return { created: true, kid: rotateJwtKey(opts).kid };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const opts = readCliOptions(process.env, argv);
  if (argv.includes('--ensure')) {
    const r = ensureJwtKeyRing(opts);
    process.stdout.write(`JWT key ring: ${r.created ? 'created' : 'kept'} (active kid ${r.kid})\n`);
    return;
  }
  const r = rotateJwtKey(opts);
  const was = r.previousKid
    ? `, previous ${r.previousKid} stays published until its tokens expire`
    : '';
  process.stdout.write(`JWT signing key rotated: active kid ${r.kid}${was}\n`);
}

if (require.main === module) runCli(main);
