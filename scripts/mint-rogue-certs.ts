#!/usr/bin/env node
/**
 * Mint the rogue certs used by `make demo-rogue` (Step 7).
 *
 * Produces:
 *   var/rogue/self-signed.{pem,key}      -- a self-signed leaf, trusted by nobody
 *   var/rogue/wrong-spiffe.{pem,key}     -- CA-signed, but URI SAN is rogue.local
 *
 * The second simulates a stolen or misissued cert that chains to the real CA
 * but claims a foreign identity. Only `checkPeer` (post-handshake) can deny it.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { createPrivateKey, randomBytes, webcrypto } from 'node:crypto';
import { issueLeaf, parseCert, selfSignedLeaf } from './lib/cert-utils';
import { writeFileAtomic, ensureDir } from './lib/fs-utils';
import { deriveSeed, deriveSerial, keyPairFromSeed } from './lib/seed';

const VAR_DIR = process.env.BASTION_VAR_DIR ?? 'var';
const ROGUE_DIR = join(VAR_DIR, 'rogue');
const ROGUE_SERVICE = 'rogue';
const ROGUE_URI = 'spiffe://rogue.local/services/rogue';
const SELF_SIGNED_URI = 'spiffe://bastion.local/services/rogue';
const KEY_MODE = 0o600;
const CERT_MODE = 0o644;

function readOptions(): { seed?: string; nowMs: number } {
  const { values } = parseArgs({
    options: { seed: { type: 'string' }, now: { type: 'string' } },
    allowPositionals: false,
  });
  const nowMs = values.now ? Date.parse(values.now) : Date.now();
  if (!Number.isFinite(nowMs)) throw new Error(`--now must be ISO 8601, got ${values.now}`);
  return { seed: values.seed, nowMs };
}

async function loadCaKey(): Promise<webcrypto.CryptoKey> {
  const keyPem = await readFile(join(VAR_DIR, 'ca', 'ca.key'), 'utf8');
  const keyObject = createPrivateKey(keyPem);
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  return webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
}

function seedOrRandom(master: string | undefined, label: string): Buffer {
  return master ? deriveSeed(master, label) : randomBytes(32);
}

function serialOrRandom(master: string | undefined, label: string): string {
  return master ? deriveSerial(master, label) : `01${randomBytes(8).toString('hex')}`;
}

async function main(): Promise<void> {
  const opts = readOptions();
  const caPem = await readFile(join(VAR_DIR, 'ca', 'ca.pem'), 'utf8');
  const caCert = parseCert(caPem);
  const caKey = await loadCaKey();

  await ensureDir(ROGUE_DIR);
  const notBefore = new Date(opts.nowMs - 60_000);
  const notAfter = new Date(opts.nowMs + 90 * 86_400_000);

  const selfPair = await keyPairFromSeed(seedOrRandom(opts.seed, 'rogue:self'));
  const selfSigned = await selfSignedLeaf(selfPair, {
    service: ROGUE_SERVICE,
    uri: SELF_SIGNED_URI,
    notBefore,
    notAfter,
    serialHex: serialOrRandom(opts.seed, 'rogue:self'),
  });
  await writeFileAtomic(join(ROGUE_DIR, 'self-signed.pem'), selfSigned.certPem, CERT_MODE);
  await writeFileAtomic(join(ROGUE_DIR, 'self-signed.key'), selfSigned.keyPem, KEY_MODE);

  const wrongPair = await keyPairFromSeed(seedOrRandom(opts.seed, 'rogue:wrong-spiffe'));
  const wrong = await issueLeaf({ cert: caCert, key: caKey }, wrongPair, {
    service: ROGUE_SERVICE,
    uri: ROGUE_URI,
    notBefore,
    notAfter,
    serialHex: serialOrRandom(opts.seed, 'rogue:wrong-spiffe'),
  });
  await writeFileAtomic(join(ROGUE_DIR, 'wrong-spiffe.pem'), wrong.certPem, CERT_MODE);
  await writeFileAtomic(join(ROGUE_DIR, 'wrong-spiffe.key'), wrong.keyPem, KEY_MODE);

  process.stdout.write(`rogue certs written under ${ROGUE_DIR}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`mint-rogue-certs failed: ${(err as Error).message}\n`);
  process.exit(1);
});
