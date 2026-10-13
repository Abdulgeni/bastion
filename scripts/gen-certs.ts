#!/usr/bin/env node
/**
 * Generate the development CA and per-service leaf certificates.
 *
 * Usage:
 *   ts-node scripts/gen-certs.ts [--seed HEX] [--now ISO8601] [--force]
 *
 * With --seed and --now the entire output is byte-identical across runs
 * (keys, serials, timestamps). Without them, fresh keys are generated and
 * the current time is used.
 *
 * The CA is never regenerated if it already exists, unless --force is given.
 * Leaf certs are re-issued when missing or when --force is passed. Use
 * `rotate-certs.ts` to re-issue leaves without touching the CA.
 */
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { createPrivateKey, randomBytes, webcrypto } from 'node:crypto';
import { createCa, issueLeaf, parseCert } from './lib/cert-utils';
import { ensureDir, writeFileAtomic } from './lib/fs-utils';
import { deriveSeed, deriveSerial, keyPairFromSeed } from './lib/seed';

const SERVICE_NAMES = ['edge', 'orders', 'inventory', 'payments'] as const;

const TRUST_DOMAIN = process.env.BASTION_TRUST_DOMAIN ?? 'bastion.local';
const VAR_DIR = process.env.BASTION_VAR_DIR ?? 'var';

const CA_KEY_MODE = 0o600;
const LEAF_KEY_MODE = 0o600;
const CERT_MODE = 0o644;
const CA_VALIDITY_DAYS = 365;
const LEAF_VALIDITY_DAYS = 90;
const CLOCK_SKEW_MS = 60_000;

interface Options {
  readonly seed: string | undefined;
  readonly nowMs: number;
  readonly force: boolean;
}

function readOptions(): Options {
  const { values } = parseArgs({
    options: {
      seed: { type: 'string' },
      now: { type: 'string' },
      force: { type: 'boolean', default: false },
    },
    allowPositionals: false,
  });
  const nowMs = values.now ? Date.parse(values.now) : Date.now();
  if (!Number.isFinite(nowMs)) {
    throw new Error(`--now must be an ISO 8601 timestamp, got ${values.now}`);
  }
  return { seed: values.seed, nowMs, force: values.force ?? false };
}

function seedFor(master: string | undefined, label: string): Buffer {
  return master === undefined ? randomBytes(32) : deriveSeed(master, label);
}

function serialFor(master: string | undefined, label: string): string {
  return master === undefined ? `01${randomBytes(8).toString('hex')}` : deriveSerial(master, label);
}

function timestamps(nowMs: number, days: number): { notBefore: Date; notAfter: Date } {
  return {
    notBefore: new Date(nowMs - CLOCK_SKEW_MS),
    notAfter: new Date(nowMs + days * 86_400_000),
  };
}

async function generateCa(opts: Options): Promise<void> {
  const caDir = join(VAR_DIR, 'ca');
  const certPath = join(caDir, 'ca.pem');
  const keyPath = join(caDir, 'ca.key');

  if (existsSync(certPath) && existsSync(keyPath) && !opts.force) {
    process.stdout.write('CA present; skipping (use --force to regenerate)\n');
    return;
  }

  const keyPair = await keyPairFromSeed(seedFor(opts.seed, 'ca'));
  const { notBefore, notAfter } = timestamps(opts.nowMs, CA_VALIDITY_DAYS);
  const ca = await createCa(keyPair, {
    name: 'bastion-dev-ca',
    notBefore,
    notAfter,
    serialHex: serialFor(opts.seed, 'ca'),
  });
  await ensureDir(caDir);
  await writeFileAtomic(certPath, ca.certPem, CERT_MODE);
  await writeFileAtomic(keyPath, ca.keyPem, CA_KEY_MODE);
  process.stdout.write(`CA written to ${certPath}\n`);
}

async function loadCa(): Promise<{ cert: ReturnType<typeof parseCert>; key: webcrypto.CryptoKey }> {
  const certPem = await readFile(join(VAR_DIR, 'ca', 'ca.pem'), 'utf8');
  const keyPem = await readFile(join(VAR_DIR, 'ca', 'ca.key'), 'utf8');
  const cert = parseCert(certPem);
  const keyObject = createPrivateKey(keyPem);
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const key = await webcrypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );
  return { cert, key };
}

async function generateLeaves(opts: Options): Promise<void> {
  const ca = await loadCa();
  const { notBefore, notAfter } = timestamps(opts.nowMs, LEAF_VALIDITY_DAYS);
  for (const service of SERVICE_NAMES) {
    const dir = join(VAR_DIR, 'certs', service);
    const certPath = join(dir, 'cert.pem');
    const keyPath = join(dir, 'key.pem');
    if (existsSync(certPath) && existsSync(keyPath) && !opts.force) {
      process.stdout.write(`leaf for ${service} present; skipping\n`);
      continue;
    }
    const keyPair = await keyPairFromSeed(seedFor(opts.seed, `leaf:${service}`));
    const leaf = await issueLeaf(ca, keyPair, {
      service,
      uri: `spiffe://${TRUST_DOMAIN}/services/${service}`,
      notBefore,
      notAfter,
      serialHex: serialFor(opts.seed, `leaf:${service}`),
    });
    await ensureDir(dir);
    await writeFileAtomic(certPath, leaf.certPem, CERT_MODE);
    await writeFileAtomic(keyPath, leaf.keyPem, LEAF_KEY_MODE);
    process.stdout.write(`leaf for ${service} written to ${certPath}\n`);
  }
}

async function main(): Promise<void> {
  const opts = readOptions();
  await generateCa(opts);
  await generateLeaves(opts);
}

main().catch((err: unknown) => {
  process.stderr.write(`gen-certs failed: ${(err as Error).message}\n`);
  process.exit(1);
});
