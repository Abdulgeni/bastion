import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import { keyPairFromSeed, privateKeyToPem } from '../../../../scripts/lib/seed';
import { JWT_REASON } from './reasons';
import { TokenIssuer } from './issuer';
import { JwksCache, type JwksHttpClient } from './jwks-cache';
import { JwtKeyStore } from './key-store';
import { ReplayCache } from './replay-cache';
import { TokenVerifier } from './verifier';

const NOW = 1_700_000_000;
const AUD = 'orders';
const ISS = 'edge';

let dir: string;
let store: JwtKeyStore;
let issuer: TokenIssuer;

class FakeHttp implements JwksHttpClient {
  constructor(private readonly jwks: unknown) {}
  async getJson(): Promise<unknown> {
    return this.jwks;
  }
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'bastion-verifier-'));
  mkdirSync(join(dir, 'jwt'), { recursive: true });
  const pair = await keyPairFromSeed(Buffer.alloc(32, 1));
  const pem = await privateKeyToPem(pair.privateKey);
  writeFileSync(join(dir, 'jwt', 'k1.pem'), pem, { flag: 'w' });
  store = await JwtKeyStore.load(dir);
  issuer = new TokenIssuer(store, new FakeClock(NOW * 1000), new SeededRandom('test'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function setup(ttl = 300) {
  const clock = new FakeClock(NOW * 1000);
  const jwks = new JwksCache({
    url: 'http://edge/jwks',
    http: new FakeHttp({ keys: store.all().map((k) => k.publicJwk) }),
    clock,
    ttlSeconds: ttl,
  });
  const replay = new ReplayCache(clock);
  const verifier = new TokenVerifier({
    serviceName: AUD,
    expectedAudience: AUD,
    expectedIssuer: ISS,
    clock,
    jwks,
    replay,
  });
  return { clock, verifier, jwks, replay };
}

async function minted(over: Partial<Parameters<TokenIssuer['issue']>[0]> = {}) {
  return issuer.issue({
    subject: 'alice',
    audience: [AUD],
    scope: ['orders:write'],
    ...over,
  });
}

describe('TokenVerifier', () => {
  it('verifies a fresh token', async () => {
    const { verifier } = setup();
    const { token } = await minted();
    const result = await verifier.verify(token);
    expect(result.ok).toBe(true);
  });

  it('rejects a missing token', async () => {
    const { verifier } = setup();
    expect(await verifier.verify(undefined)).toMatchObject({ reason: JWT_REASON.MISSING });
    expect(await verifier.verify('')).toMatchObject({ reason: JWT_REASON.MISSING });
  });

  it('rejects a token whose kid is missing', async () => {
    const { verifier } = setup();
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const fake = `${header}.${header}.signature`;
    expect(await verifier.verify(fake)).toMatchObject({ reason: JWT_REASON.MALFORMED });
  });

  it('rejects a tampered payload with BAD_SIG', async () => {
    const { verifier } = setup();
    const { token } = await minted();
    const parts = token.split('.');
    const header = parts[0];
    const signature = parts[2];
    const badPayload = Buffer.from(JSON.stringify({ sub: 'mallory' })).toString('base64url');
    const result = await verifier.verify(`${header}.${badPayload}.${signature}`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect([JWT_REASON.BAD_SIG, JWT_REASON.MALFORMED]).toContain(result.reason);
    }
  });

  it('rejects a replayed token', async () => {
    const { verifier } = setup();
    const { token } = await minted();
    expect((await verifier.verify(token)).ok).toBe(true);
    expect(await verifier.verify(token)).toMatchObject({ reason: JWT_REASON.REPLAYED });
  });

  it('rejects a token whose audience is wrong', async () => {
    const { verifier } = setup();
    const { token } = await minted({ audience: ['payments'] });
    const result = await verifier.verify(token);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect([JWT_REASON.BAD_AUD, JWT_REASON.MALFORMED]).toContain(result.reason);
    }
  });

  it('reports JWKS_UNAVAILABLE when the cache cannot fetch', async () => {
    const clock = new FakeClock(NOW * 1000);
    const jwks = new JwksCache({
      url: 'http://edge/jwks',
      http: {
        getJson: async () => {
          throw new Error('down');
        },
      },
      clock,
    });
    const verifier = new TokenVerifier({
      serviceName: AUD,
      expectedAudience: AUD,
      expectedIssuer: ISS,
      clock,
      jwks,
      replay: new ReplayCache(clock),
    });
    const { token } = await minted();
    expect(await verifier.verify(token)).toMatchObject({ reason: JWT_REASON.JWKS_UNAVAILABLE });
  });
});
