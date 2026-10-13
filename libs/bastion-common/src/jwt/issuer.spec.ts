import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { jwtVerify } from 'jose';
import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import { keyPairFromSeed, privateKeyToPem } from '../../../../scripts/lib/seed';
import { TokenIssuer } from './issuer';
import { JwtKeyStore } from './key-store';

const NOW = 1_700_000_000;

let dir: string;
let store: JwtKeyStore;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'bastion-issuer-'));
  mkdirSync(join(dir, 'jwt'), { recursive: true });
  for (const kid of ['k1', 'k2']) {
    const seed = Buffer.alloc(32, kid === 'k1' ? 1 : 2);
    const pair = await keyPairFromSeed(seed);
    const pem = await privateKeyToPem(pair.privateKey);
    writeFileSync(join(dir, 'jwt', `${kid}.pem`), pem, { flag: 'w' });
  }
  store = await JwtKeyStore.load(dir);
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function issuer(at = NOW): TokenIssuer {
  return new TokenIssuer(store, new FakeClock(at * 1000), new SeededRandom('test-seed'));
}

describe('TokenIssuer', () => {
  it('signs a token with the current kid', async () => {
    const result = await issuer().issue({
      subject: 'alice',
      audience: ['orders'],
      scope: ['orders:write'],
    });
    expect(result.token.split('.')).toHaveLength(3);
    const header = JSON.parse(
      Buffer.from(result.token.split('.')[0], 'base64url').toString(),
    ) as Record<string, unknown>;
    expect(header).toMatchObject({ alg: 'EdDSA', typ: 'JWT', kid: 'k2' });
  });

  it('sets sub, aud, scope, iss, iat, exp, jti', async () => {
    const { claims } = await issuer().issue({
      subject: 'alice',
      audience: ['orders', 'inventory'],
      scope: ['orders:write', 'inventory:reserve'],
    });
    expect(claims.sub).toBe('alice');
    expect(claims.aud).toEqual(['orders', 'inventory']);
    expect(claims.scope).toEqual(['orders:write', 'inventory:reserve']);
    expect(claims.iss).toBe('edge');
    // iat = now - 5 (skew), exp = iat + 300 (ttl) + 5 (skew). Difference = 305.
    expect(claims.exp - claims.iat).toBe(305);
  });

  it('produces a token that verifies with the public JWK', async () => {
    const result = await issuer().issue({
      subject: 'alice',
      audience: ['orders'],
      scope: ['orders:write'],
    });
    const jwk = store.get('k2')!.publicJwk;
    const { payload } = await jwtVerify(result.token, jwk, {
      currentDate: new Date(NOW * 1000),
      clockTolerance: 5,
    });
    expect(payload.sub).toBe('alice');
    expect(payload.aud).toEqual(['orders']);
  });

  it('uses the custom ttl when given', async () => {
    const { claims } = await issuer().issue({
      subject: 'alice',
      audience: ['orders'],
      scope: [],
      ttlSeconds: 60,
      skewSeconds: 0,
    });
    expect(claims.exp - claims.iat).toBe(60);
  });

  it('is deterministic with a seeded random', async () => {
    const a = await issuer().issue({ subject: 'alice', audience: ['orders'], scope: [] });
    const b = await issuer().issue({ subject: 'alice', audience: ['orders'], scope: [] });
    expect(a.claims.jti.slice(-8)).toBe(b.claims.jti.slice(-8));
  });
});
