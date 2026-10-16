import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import { JwtKeyStore } from '../libs/bastion-common/src/jwt/key-store';
import { TokenIssuer } from '../libs/bastion-common/src/jwt/issuer';
import { ReplayCache } from '../libs/bastion-common/src/jwt/replay-cache';
import { JwksCache } from '../libs/bastion-common/src/jwt/jwks-cache';
import { TokenVerifier } from '../libs/bastion-common/src/jwt/verifier';
import { JWT_REASON } from '../libs/bastion-common/src/jwt/reasons';
import { buildJwks } from '../libs/bastion-common/src/jwt/jwks';
import { SeededRandom } from '../libs/bastion-common/src/random/random-source';
import { testOptions, tmpVar } from './pki/test-helpers';
import { ensureJwtKeyRing } from './rotate-jwt';
import { tamperPayload } from './forge-token';

const FIXED_NOW = Date.UTC(2026, 9, 12, 12, 0, 0);

/**
 * A tiny in-memory Bastion: one key store, an issuer, a JWKS cache that reads
 * from the same store, and a verifier for `orders`.
 */
async function makeWorld(seed = 'forge') {
  const dir = tmpVar();
  const opts = testOptions(dir, { random: new SeededRandom(seed), clock: new FakeClock(FIXED_NOW) });
  ensureJwtKeyRing(opts);

  const store = await JwtKeyStore.load(dir);
  const clock = new FakeClock(FIXED_NOW);
  const random = new SeededRandom(`${seed}-issuer`);
  const issuer = new TokenIssuer(store, clock, random, 'edge');
  const jwks = new JwksCache({
    url: 'http://edge/jwks',
    clock,
    http: { getJson: async () => buildJwks(store) },
  });
  const replay = new ReplayCache(clock);
  const verifier = new TokenVerifier({
    serviceName: 'orders',
    expectedAudience: 'orders',
    expectedIssuer: 'edge',
    clock,
    jwks,
    replay,
  });
  return { dir, store, clock, random, issuer, verifier, replay };
}

describe('forge-token scenarios', () => {
  it('(a) a token addressed only to payments is bad_aud at orders', async () => {
    const w = await makeWorld();
    const { token } = await w.issuer.issue({
      subject: 'alice',
      audience: ['payments'],
      scope: ['payments:charge'],
    });
    expect(await w.verifier.verify(token)).toMatchObject({
      ok: false,
      reason: JWT_REASON.BAD_AUD,
    });
  });

  it('(b) editing the audience of a valid token breaks the signature: bad_sig', async () => {
    const w = await makeWorld();
    const { token } = await w.issuer.issue({
      subject: 'alice',
      audience: ['orders'],
      scope: ['orders:write'],
    });
    const tampered = tamperPayload(token, { aud: ['payments'] });
    expect(await w.verifier.verify(tampered)).toMatchObject({
      ok: false,
      reason: JWT_REASON.BAD_SIG,
    });
  });

  it('(c) a valid token works once and its second use is jwt+replayed', async () => {
    const w = await makeWorld();
    const { token } = await w.issuer.issue({
      subject: 'alice',
      audience: ['orders'],
      scope: ['orders:write'],
    });
    expect((await w.verifier.verify(token)).ok).toBe(true);
    expect(await w.verifier.verify(token)).toMatchObject({
      ok: false,
      reason: JWT_REASON.REPLAYED,
    });
  });
});

describe('tamperPayload', () => {
  it('keeps the original header and signature', async () => {
    const w = await makeWorld();
    const { token } = await w.issuer.issue({
      subject: 'alice',
      audience: ['orders'],
      scope: ['orders:write'],
    });
    const [h, , s] = token.split('.');
    const edited = tamperPayload(token, { sub: 'mallory' }).split('.');
    expect(edited[0]).toBe(h);
    expect(edited[2]).toBe(s);
  });

  it('refuses input that is not a compact JWS', () => {
    expect(() => tamperPayload('nope', { a: 1 })).toThrow(/compact JWS/);
    expect(() => tamperPayload('a.b', { a: 1 })).toThrow(/compact JWS/);
    expect(() => tamperPayload('a.b.c.d', { a: 1 })).toThrow(/compact JWS/);
  });
});
