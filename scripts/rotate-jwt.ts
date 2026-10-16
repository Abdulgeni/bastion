import { existsSync, readFileSync } from 'node:fs';
import {
  defaultKeyRingPath,
  generateSigningKey,
  parseKeyRing,
  rotateKeyRing,
  serializeKeyRing,
  type KeyRing,
} from '../libs/bastion-common/src/jwt/key-ring';
import { readCliOptions, runCli, type PkiOptions } from './pki/cli-options';
import { writePrivate } from './pki/layout';

export interface JwtKeyResult {
  readonly kid: string;
  readonly previousKid?: string;
  readonly keyCount: number;
}

type JwtKeyOptions = Pick<PkiOptions, 'varDir' | 'random' | 'clock'>;

function loadRing(path: string): KeyRing | undefined {
  return existsSync(path) ? parseKeyRing(readFileSync(path, 'utf8')) : undefined;
}

export function rotateJwtKey(opts: JwtKeyOptions): JwtKeyResult {
  const path = defaultKeyRingPath(opts.varDir);
  const previous = loadRing(path);
  const key = generateSigningKey(opts.random, opts.clock.nowMs());
  const ring = rotateKeyRing(previous, key, opts.clock.nowMs());
  writePrivate(path, serializeKeyRing(ring));
  const result = { kid: key.kid, keyCount: ring.keys.length };
  return previous ? { ...result, previousKid: previous.active } : result;
}

export function ensureJwtKeyRing(opts: JwtKeyOptions): { created: boolean; kid: string } {
  const existing = loadRing(defaultKeyRingPath(opts.varDir));
  if (existing) return { created: false, kid: existing.active };
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
  const was = r.previousKid ? `, previous ${r.previousKid} stays published until its tokens expire` : '';
  process.stdout.write(`JWT signing key rotated: active kid ${r.kid}${was} (${r.keyCount} keys)\n`);
}

if (require.main === module) runCli(main);
