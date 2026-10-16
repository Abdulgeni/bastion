import {
  createHash,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ConfigError } from '../errors';
import type { RandomSource } from '../random/random-source';
import { TOKEN_TTL_SECONDS } from './claims';

/** Extra time a retired key stays published after its last possible token has expired. */
export const KEY_GRACE_SECONDS = 60;

/** ASN.1 PKCS#8 header for an Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** One Ed25519 signing key. `retiredAtMs` is set once a newer key has replaced it. */
export interface SigningKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly privateKeyPem: string;
  readonly createdAtMs: number;
  readonly retiredAtMs?: number;
}

/** All signing keys edge knows. Exactly one (`active`) signs; retired ones only keep verifying. */
export interface KeyRing {
  readonly active: string;
  readonly keys: readonly SigningKey[];
}

/** A public key as published in the JWKS. */
export interface PublicJwk {
  readonly kty: 'OKP';
  readonly crv: 'Ed25519';
  readonly x: string;
  readonly kid: string;
  readonly alg: 'EdDSA';
  readonly use: 'sig';
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) of an Ed25519 public key; used as the `kid`. */
export function kidFor(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' });
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  return createHash('sha256').update(canonical).digest('base64url');
}

function buildKey(privateKey: KeyObject, createdAtMs: number, retiredAtMs?: number): SigningKey {
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const kid = kidFor(createPublicKey(privateKey));
  return retiredAtMs === undefined
    ? { kid, privateKey, privateKeyPem: pem, createdAtMs }
    : { kid, privateKey, privateKeyPem: pem, createdAtMs, retiredAtMs };
}

/** Creates a signing key from 32 bytes of `random` (reproducible with a seeded source). */
export function generateSigningKey(random: RandomSource, nowMs: number): SigningKey {
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, random.bytes(32)]);
  return buildKey(createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' }), nowMs);
}

/** The key that currently signs new tokens. */
export function activeKey(ring: KeyRing): SigningKey {
  const key = ring.keys.find((k) => k.kid === ring.active);
  if (!key) throw new Error('key ring has no active key');
  return key;
}

/** True while a key can still matter: active, or retired less than TTL + grace ago. */
export function isPublishable(key: SigningKey, nowMs: number): boolean {
  if (key.retiredAtMs === undefined) return true;
  return nowMs < key.retiredAtMs + (TOKEN_TTL_SECONDS + KEY_GRACE_SECONDS) * 1000;
}

/**
 * Adds `newKey` as the active key. The previous active key is retired (it keeps
 * verifying in-flight tokens), and keys retired for longer than TTL + grace are dropped.
 */
export function rotateKeyRing(ring: KeyRing | undefined, newKey: SigningKey, nowMs: number): KeyRing {
  const kept = (ring?.keys ?? [])
    .map((k) => (k.kid === ring?.active ? buildKey(k.privateKey, k.createdAtMs, nowMs) : k))
    .filter((k) => isPublishable(k, nowMs));
  return { active: newKey.kid, keys: [newKey, ...kept] };
}

/** The JWKS document for `/.well-known/jwks.json`: active key first, then retired keys still in grace. */
export function publicJwks(ring: KeyRing, nowMs: number): { keys: PublicJwk[] } {
  const keys = ring.keys
    .filter((k) => isPublishable(k, nowMs))
    .sort((a, b) => Number(b.kid === ring.active) - Number(a.kid === ring.active))
    .map((k): PublicJwk => {
      const jwk = createPublicKey(k.privateKey).export({ format: 'jwk' });
      return { kty: 'OKP', crv: 'Ed25519', x: String(jwk.x), kid: k.kid, alg: 'EdDSA', use: 'sig' };
    });
  return { keys };
}

/** Serialises a ring for var/jwt/keys.json (contains private keys: write with mode 0600). */
export function serializeKeyRing(ring: KeyRing): string {
  const keys = ring.keys.map((k) => ({
    kid: k.kid,
    privateKeyPem: k.privateKeyPem,
    createdAtMs: k.createdAtMs,
    ...(k.retiredAtMs === undefined ? {} : { retiredAtMs: k.retiredAtMs }),
  }));
  return `${JSON.stringify({ version: 1, active: ring.active, keys }, null, 2)}\n`;
}

function parseKey(raw: unknown, issues: string[]): SigningKey | undefined {
  const r = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  try {
    const privateKey = createPrivateKey(String(r.privateKeyPem));
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('not ed25519');
    const created = Number(r.createdAtMs);
    const retired = r.retiredAtMs === undefined ? undefined : Number(r.retiredAtMs);
    if (!Number.isFinite(created) || (retired !== undefined && !Number.isFinite(retired))) {
      throw new Error('bad timestamp');
    }
    const key = buildKey(privateKey, created, retired);
    if (key.kid !== r.kid) throw new Error('kid does not match key');
    return key;
  } catch {
    issues.push('JWT key ring contains an invalid or inconsistent key');
    return undefined;
  }
}

/** Parses and validates a key ring file's text. Throws ConfigError (never echoing key material). */
export function parseKeyRing(text: string): KeyRing {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new ConfigError(['JWT key ring is not valid JSON']);
  }
  const d = (typeof doc === 'object' && doc !== null ? doc : {}) as Record<string, unknown>;
  if (d.version !== 1 || typeof d.active !== 'string' || !Array.isArray(d.keys) || d.keys.length < 1 || d.keys.length > 10) {
    throw new ConfigError(['JWT key ring has an unsupported shape']);
  }
  const issues: string[] = [];
  const keys = d.keys.map((k) => parseKey(k, issues)).filter((k): k is SigningKey => k !== undefined);
  const actives = keys.filter((k) => k.retiredAtMs === undefined);
  if (actives.length !== 1 || actives[0]?.kid !== d.active) {
    issues.push('JWT key ring must have exactly one active (unretired) key, named by "active"');
  }
  if (issues.length > 0) throw new ConfigError([...new Set(issues)]);
  return { active: d.active, keys };
}

/** Default location of the key ring under var/. Only edge may read it. */
export function defaultKeyRingPath(varDir: string): string {
  return join(varDir, 'jwt', 'keys.json');
}

/** Reads and validates a key ring file; throws ConfigError if it is missing or invalid. */
export function readKeyRingFile(path: string): KeyRing {
  try {
    return parseKeyRing(readFileSync(path, 'utf8'));
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    const code = (err as NodeJS.ErrnoException).code ?? 'UNKNOWN';
    throw new ConfigError([`JWT_KEYS_FILE: cannot read ${path} (${code})`]);
  }
}

/** A key ring file that is re-read whenever it changes, so `rotate-jwt` takes effect without a restart. */
export class KeyRingFile {
  private ring: KeyRing | undefined;
  private stamp = '';

  constructor(private readonly path: string) {}

  /** The current ring. Throws ConfigError if the file is missing or invalid. */
  get(): KeyRing {
    const st = statSync(this.path, { throwIfNoEntry: false });
    const stamp = st ? `${st.mtimeMs}:${st.size}` : '';
    if (this.ring === undefined || stamp !== this.stamp) {
      this.ring = readKeyRingFile(this.path);
      this.stamp = stamp;
    }
    return this.ring;
  }
}
