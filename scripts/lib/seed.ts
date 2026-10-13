/**
 * Deterministic key and identifier derivation from a master seed.
 *
 * Ed25519 keys are constructed by wrapping a 32-byte seed in the fixed PKCS#8
 * structure from RFC 8410 (section 7). This lets tests ask for a specific
 * master seed and get byte-identical keys, serials, and identifiers.
 */
import { createHash, webcrypto, type JsonWebKey } from 'node:crypto';

// RFC 8410 PKCS#8 header for an Ed25519 private key (algorithm OID 1.3.101.112).
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const ALG = { name: 'Ed25519' } as const;

/** Derive 32 bytes for a specific labelled use from a master seed. */
export function deriveSeed(masterSeed: string, label: string): Buffer {
  return createHash('sha256').update(masterSeed).update(':').update(label).digest();
}

/** Derive a serial number: 18-char hex starting with "01" (always positive). */
export function deriveSerial(masterSeed: string, label: string): string {
  const digest = createHash('sha256')
    .update(masterSeed)
    .update(':serial:')
    .update(label)
    .digest('hex');
  return `01${digest.slice(0, 16)}`;
}

/** Build an Ed25519 key pair from a 32-byte seed. */
export async function keyPairFromSeed(seed: Buffer): Promise<webcrypto.CryptoKeyPair> {
  if (seed.length !== 32) {
    throw new RangeError('Ed25519 seed must be exactly 32 bytes');
  }
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = await webcrypto.subtle.importKey('pkcs8', pkcs8, ALG, true, ['sign']);
  const jwk = (await webcrypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey & {
    x?: string;
  };
  if (typeof jwk.x !== 'string' || jwk.x.length === 0) {
    throw new Error('Ed25519 private key did not expose a public component (jwk.x)');
  }
  const publicKey = await webcrypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
    ALG,
    true,
    ['verify'],
  );
  return { privateKey, publicKey };
}

/** Export a private CryptoKey as PKCS#8 PEM. */
export async function privateKeyToPem(key: webcrypto.CryptoKey): Promise<string> {
  const der = await webcrypto.subtle.exportKey('pkcs8', key);
  return pemEncode(Buffer.from(der), 'PRIVATE KEY');
}

/** Base64 PEM wrapping with 64-char lines. */
export function pemEncode(der: Buffer, label: string): string {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
