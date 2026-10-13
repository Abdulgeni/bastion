import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { exportJWK, importPKCS8, type JWK, type KeyLike } from 'jose';
import { ConfigError } from '../errors';

const ALG = { name: 'Ed25519' } as const;

/** One signing key Bastion can mint tokens with. */
export interface SigningKey {
  readonly kid: string;
  readonly key: KeyLike;
  readonly publicJwk: JWK;
}

/**
 * The set of JWT signing keys this process can use. Exactly one is "current"
 * (the one the issuer will use); every key in the set is published in JWKS so
 * tokens signed with older keys keep verifying until they expire.
 *
 * Filesystem layout: `<varDir>/jwt/<kid>.pem`, PKCS#8 PEM, one file per key.
 * The current key is selected by `currentKid`, or the lexicographically
 * largest filename by default.
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
    const keys = new Map<string, SigningKey>();
    for (const { kid, pem } of files) {
      const signingKey = await loadSigningKey(kid, pem);
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

/**
 * Import a PKCS#8 PEM for signing, then re-import only the public half so the
 * JWK we publish has no private component. jose's `jwtVerify` rejects private
 * JWKs, so this split is required.
 */
async function loadSigningKey(kid: string, pem: string): Promise<SigningKey> {
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
  };
}
