import { createPrivateKey, createPublicKey, webcrypto } from 'node:crypto';
import type { RandomSource } from '../../libs/bastion-common/src/random/random-source';

/** ASN.1 PKCS#8 header for an Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519 = { name: 'Ed25519' };

export interface KeyMaterial {
  readonly privateKey: webcrypto.CryptoKey;
  readonly publicKey: webcrypto.CryptoKey;
  /** The private key as a PKCS#8 PEM string. */
  readonly privateKeyPem: string;
}

/**
 * Derives an Ed25519 key pair from 32 bytes of `random`. With the OS CSPRNG this is
 * an ordinary random key; with a seeded source (tests only) it is reproducible.
 */
export async function deriveEd25519Keys(random: RandomSource): Promise<KeyMaterial> {
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, random.bytes(32)]);
  const nodeKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(nodeKey).export({ format: 'der', type: 'spki' });
  const [privateKey, publicKey] = await Promise.all([
    webcrypto.subtle.importKey('pkcs8', pkcs8, ED25519, true, ['sign']),
    webcrypto.subtle.importKey('spki', spki, ED25519, true, ['verify']),
  ]);
  const privateKeyPem = nodeKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  return { privateKey, publicKey, privateKeyPem };
}

/** Imports an Ed25519 PKCS#8 PEM private key for signing. Throws for any other key type. */
export async function importSigningKey(pem: string): Promise<webcrypto.CryptoKey> {
  const nodeKey = createPrivateKey(pem);
  if (nodeKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('expected an Ed25519 private key');
  }
  const der = nodeKey.export({ format: 'der', type: 'pkcs8' });
  return webcrypto.subtle.importKey('pkcs8', der, ED25519, true, ['sign']);
}
