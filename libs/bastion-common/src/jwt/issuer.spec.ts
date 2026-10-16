import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import { JwtIssuer } from './issuer';
import { generateSigningKey, rotateKeyRing, type KeyRing } from './key-ring';
import { NOW } from './test-helpers';

function fixture(seed = 's') {
  const clock = new FakeClock(NOW);
  const random = new SeededRandom(seed);
  let ring: KeyRing = rotateKeyRing(undefined, generateSigningKey(random, NOW), NOW);
  const issuer = new JwtIssuer({ ring: () => ring, clock, random });
  return {
    issuer,
    clock,
    kid: () => ring.active,
    rotate: () => {
      ring = rotateKeyRing(ring, generateSigningKey(random, NOW), NOW);
    },
  };
}

const decode = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));

describe('JwtIssuer', () => {
  it('issues a 5-minute token addressed to every service', async () => {
    const f = fixture();
    const issued = await f.issuer.issue({ sub: 'alice', scope: ['orders:write', 'payments:charge'] });
    const [header, payload] = issued.token.split('.');
    expect(decode(header as string)).toEqual({ alg: 'EdDSA', kid: f.kid(), typ: 'JWT' });
    expect(decode(payload as string)).toEqual(issued.claims);
    expect(issued.claims).toMatchObject({
      iss: 'bastion-edge',
      sub: 'alice',
      aud: ['orders', 'inventory', 'payments'],
      iat: NOW / 1000,
      exp: NOW / 1000 + 300,
      scope: ['orders:write', 'payments:charge'],
    });
    expect(issued.claims.jti).toMatch(/^[0-9a-f]{32}$/);
  });

  it('gives every token a fresh jti', async () => {
    const f = fixture();
    const a = await f.issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    const b = await f.issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    expect(a.claims.jti).not.toBe(b.claims.jti);
  });

  it('is byte-identical for the same seed and clock', async () => {
    const a = await fixture('same').issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    const b = await fixture('same').issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    expect(a.token).toBe(b.token);
    const c = await fixture('other').issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    expect(c.token).not.toBe(a.token);
  });

  it('signs with the newly active key after a rotation', async () => {
    const f = fixture();
    const before = f.kid();
    f.rotate();
    const issued = await f.issuer.issue({ sub: 'alice', scope: ['orders:write'] });
    expect(issued.kid).toBe(f.kid());
    expect(issued.kid).not.toBe(before);
  });

  it.each([
    ['bad subject', { sub: 'a b', scope: ['orders:write'] }],
    ['empty subject', { sub: '', scope: ['orders:write'] }],
    ['no scopes', { sub: 'alice', scope: [] }],
    ['unknown scope', { sub: 'alice', scope: ['admin:all'] }],
  ])('rejects %s', async (_name, req) => {
    await expect(fixture().issuer.issue(req as never)).rejects.toThrow(RangeError);
  });
});
