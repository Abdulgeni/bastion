import { createHash, createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { exportJWK, importPKCS8, type JWK, type KeyLike } from 'jose';
import { ConfigError } from '../errors';
import type { RandomSource } from '../random/random-source';

const ALG = { name: 'Ed25519' } as const;

/** ASN.1 PKCS#8 header for an Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Token lifetime that bounds how long a retired key must stay published. */
export const TOKEN_TTL_SECONDS = 300;

/** Extra seconds a retired key stays published after its last possible token expires. */
export const KEY_GRACE_SECONDS = 60;

/**
 * One signing key Bastion can mint tokens with.
 *
 * `retiredAtSec` is set once a newer key replaces this one. A retired key is
 * still published in JWKS until `retiredAtSec + TOKEN_TTL_SECONDS +
 * KEY_GRACE_SECONDS`, so any token signed just before retirement can still be
 * verified. An unretired key has `retiredAtSec === undefined`.
 */
export interface SigningKey {
  readonly kid: string;
  readonly key: KeyLike;
  readonly publicJwk: JWK;
  readonly retiredAtSec?: number;
}

/**
 * The set of JWT signing keys this process can use. Exactly one is "current"
 * (the one the issuer will use); every key in the set is published in JWKS so
 * tokens signed with older keys keep verifying until they expire.
 *
 * Filesystem layout: `<varDir>/jwt/<kid>.pem`, PKCS#8 PEM, one file per key.
 * The current key is selected by `currentKid`, or the lexicographically
 * largest filename by default.
 *
 * The retirement timestamps are held **outside** the `.pem` files, in a
 * sibling `retired.json`, because PEM files have no room for metadata.
 */
export class JwtKeyStore {
  private constructor(
    private readonly keys: ReadonlyMap<string, SigningKey>,
    readonly currentKid: string,
  ) {}

  static async load(varDir: string, currentKid?: string): Promise<JwtKeyStore> {
    const dir = join(varDir, 'jwt');
    const files = await readKeyFiles(dir);
    if (files.length === 0) {
      throw new ConfigError([`no JWT signing keys in ${dir}`]);
    }
    const retired = await readRetiredMap(dir);
    const keys = new Map<string, SigningKey>();
    for (const { kid, pem } of files) {
      const signingKey = await loadSigningKey(kid, pem, retired[kid]);
      keys.set(kid, signingKey);
    }
    const chosen = currentKid ?? [...keys.keys()].sort().at(-1);
    if (chosen === undefined || !keys.has(chosen)) {
      throw new ConfigError([
        `BASTION_JWT_CURRENT_KID=${currentKid ?? '(unset)'} not found in ${dir}`,
      ]);
    }
    return new JwtKeyStore(keys, chosen);
  }

  /** The key to sign new tokens with. */
  current(): SigningKey {
    const key = this.keys.get(this.currentKid);
    if (key === undefined) {
      throw new Error('current signing key disappeared');
    }
    return key;
  }

  /** Every key, for JWKS publication. Sorted by kid for determinism. */
  all(): SigningKey[] {
    return [...this.keys.values()].sort((a, b) => a.kid.localeCompare(b.kid));
  }

  /** Lookup by kid; used by the verifier for a token's `kid` header. */
  get(kid: string): SigningKey | undefined {
    return this.keys.get(kid);
  }
}

interface KeyFile {
  readonly kid: string;
  readonly pem: string;
}

async function readKeyFiles(dir: string): Promise<KeyFile[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return [];
  }
  const out: KeyFile[] = [];
  for (const name of entries) {
    if (!name.endsWith('.pem')) continue;
    const kid = name.slice(0, -'.pem'.length);
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(kid)) continue;
    const pem = await readFile(join(dir, name), 'utf8');
    out.push({ kid, pem });
  }
  return out.sort((a, b) => a.kid.localeCompare(b.kid));
}

/** Reads `retired.json` (kid → retiredAtSec) if present, else an empty map. */
async function readRetiredMap(dir: string): Promise<Record<string, number>> {
  try {
    const raw = await readFile(join(dir, 'retired.json'), 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new ConfigError(['JWT retired.json has an unsupported shape']);
    }
    const out: Record<string, number> = {};
    for (const [kid, at] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof at === 'number' && Number.isFinite(at)) out[kid] = at;
    }
    return out;
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return {};
    throw new ConfigError([`JWT retired.json could not be read (${code ?? 'UNKNOWN'})`]);
  }
}

/**
 * Import a PKCS#8 PEM for signing, then re-import only the public half so the
 * JWK we publish has no private component. jose's `jwtVerify` rejects private
 * JWKs, so this split is required.
 */
async function loadSigningKey(
  kid: string,
  pem: string,
  retiredAtSec: number | undefined,
): Promise<SigningKey> {
  let signingKey: KeyLike;
  try {
    signingKey = await importPKCS8(pem, 'EdDSA');
  } catch {
    throw new ConfigError([`JWT key ${kid} is not a valid Ed25519 PKCS#8 PEM`]);
  }
  const jwk = (await exportJWK(signingKey)) as JWK & { x?: string };
  if (typeof jwk.x !== 'string' || jwk.x.length === 0) {
    throw new ConfigError([`JWT key ${kid} did not expose a public component`]);
  }
  const publicKey = await webcrypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    ALG,
    true,
    ['verify'],
  );
  const publicJwk = await exportJWK(publicKey);
  return {
    kid,
    key: signingKey,
    publicJwk: { ...publicJwk, kid, alg: 'EdDSA', use: 'sig' },
    ...(retiredAtSec === undefined ? {} : { retiredAtSec }),
  };
}

/**
 * Generates a fresh Ed25519 private key from `random`, derives its public
 * `kid` from the RFC 7638 JWK thumbprint (SHA-256, base64url), and returns
 * the PKCS#8 PEM alongside the kid. Deterministic for a seeded RandomSource.
 */
export function generateSigningKeyPem(random: RandomSource): { kid: string; pem: string } {
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, random.bytes(32)]);
  const nodeKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pem = nodeKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const jwk = createPublicKey(nodeKey).export({ format: 'jwk' });
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  const kid = createHash('sha256').update(canonical).digest('base64url');
  return { kid, pem };
}

/** Writes `<dir>/<kid>.pem` with mode 0600, creating `<dir>` if needed. */
export async function writeSigningKeyPem(dir: string, kid: string, pem: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, `${kid}.pem`), pem, { mode: 0o600 });
}

/**
 * Updates `<dir>/retired.json`: keys older than TTL + grace are dropped, and
 * `retire` (if given) is added with the current time.
 */
export async function updateRetiredMap(
  dir: string,
  existing: Readonly<Record<string, number>>,
  nowSec: number,
  retire?: string,
): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  const cutoff = nowSec - (TOKEN_TTL_SECONDS + KEY_GRACE_SECONDS);
  for (const [kid, at] of Object.entries(existing)) {
    if (at > cutoff) out[kid] = at;
  }
  if (retire !== undefined) out[retire] = nowSec;
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'retired.json'), `${JSON.stringify(out, null, 2)}\n`, { mode: 0o600 });
  return out;
}
