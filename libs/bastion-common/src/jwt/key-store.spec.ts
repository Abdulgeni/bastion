import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignJWT, jwtVerify } from 'jose';
import { ConfigError } from '../errors';
import { keyPairFromSeed, privateKeyToPem } from '../../../../scripts/lib/seed';
import { JwtKeyStore } from './key-store';

let dir: string;
let seedA: Buffer;
let seedB: Buffer;

beforeAll(() => {
  seedA = Buffer.alloc(32, 1);
  seedB = Buffer.alloc(32, 2);
});

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'bastion-jwt-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

async function writeKey(kid: string, seed: Buffer): Promise<void> {
  const pair = await keyPairFromSeed(seed);
  const pem = await privateKeyToPem(pair.privateKey);
  writeFileSync(join(dir, 'jwt', `${kid}.pem`), pem, { flag: 'w' });
}

async function seedDir(): Promise<void> {
  mkdirSync(join(dir, 'jwt'), { recursive: true });
  await writeKey('k1', seedA);
  await writeKey('k2', seedB);
}

describe('JwtKeyStore', () => {
  it('loads every .pem and picks the largest kid as current by default', async () => {
    await seedDir();
    const store = await JwtKeyStore.load(dir);
    expect(store.currentKid).toBe('k2');
    expect(store.all().map((k) => k.kid)).toEqual(['k1', 'k2']);
  });

  it('honours an explicit current kid', async () => {
    await seedDir();
    const store = await JwtKeyStore.load(dir, 'k1');
    expect(store.currentKid).toBe('k1');
  });

  it('rejects an unknown current kid', async () => {
    await seedDir();
    await expect(JwtKeyStore.load(dir, 'nope')).rejects.toThrow(ConfigError);
  });

  it('rejects an empty key directory', async () => {
    await expect(JwtKeyStore.load(dir)).rejects.toThrow(ConfigError);
  });

  it('ignores files that are not valid kid names', async () => {
    await seedDir();
    writeFileSync(join(dir, 'jwt', 'has.dots.pem'), 'junk');
    writeFileSync(join(dir, 'jwt', 'not-a-pem.txt'), 'junk');
    const store = await JwtKeyStore.load(dir);
    expect(store.all().map((k) => k.kid)).toEqual(['k1', 'k2']);
  });

  it('rejects an invalid PEM', async () => {
    mkdirSync(join(dir, 'jwt'), { recursive: true });
    writeFileSync(join(dir, 'jwt', 'bad.pem'), 'not a key', { flag: 'w' });
    await expect(JwtKeyStore.load(dir)).rejects.toThrow(ConfigError);
  });

  it('publishes a JWK that verifies a token signed with the same key', async () => {
    await seedDir();
    const store = await JwtKeyStore.load(dir, 'k1');
    const { key } = store.current();
    const token = await new SignJWT({ test: true })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);
    const jwk = store.get('k1')?.publicJwk;
    expect(jwk).toBeDefined();
    const { payload } = await jwtVerify(token, jwk!, { clockTolerance: 5 });
    expect(payload.test).toBe(true);
  });

  it('looks up a key by kid', async () => {
    await seedDir();
    const store = await JwtKeyStore.load(dir);
    expect(store.get('k1')?.kid).toBe('k1');
    expect(store.get('nope')).toBeUndefined();
  });
});
