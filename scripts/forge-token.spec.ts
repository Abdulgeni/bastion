import { defaultKeyRingPath, readKeyRingFile } from '../libs/bastion-common/src/jwt/key-ring';
import { makeWorld } from '../libs/bastion-common/src/jwt/test-helpers';
import { forgeToken, tamperPayload } from './forge-token';
import { testOptions, tmpVar } from './pki/test-helpers';
import { ensureJwtKeyRing } from './rotate-jwt';

async function demoWorld() {
  const dir = tmpVar();
  ensureJwtKeyRing(testOptions(dir));
  return makeWorld({ ring: readKeyRingFile(defaultKeyRingPath(dir)) });
}

describe('stolen-JWT demo scenarios', () => {
  it('(a) a genuinely signed token addressed only to payments is bad_aud at orders', async () => {
    const w = await demoWorld();
    const token = await forgeToken({ ring: w.ring, clock: w.clock, random: w.random, aud: ['payments'] });
    expect(await w.verifier('orders').verify(token)).toMatchObject({ reason: 'jwt+bad_aud', status: 401 });
  });

  it('(b) editing the audience of a valid token breaks the signature: bad_sig, not bad_aud', async () => {
    const w = await demoWorld();
    const tampered = tamperPayload(await w.token(), { aud: ['payments'] });
    expect(await w.verifier('orders').verify(tampered)).toMatchObject({ reason: 'jwt+bad_sig', status: 401 });
  });

  it('(c) a valid token works once and its replay is jwt+replayed', async () => {
    const w = await demoWorld();
    const token = await w.token();
    const orders = w.verifier('orders');
    expect((await orders.verify(token)).ok).toBe(true);
    expect(await orders.verify(token)).toMatchObject({ reason: 'jwt+replayed', status: 401 });
  });
});

describe('forgeToken and tamperPayload', () => {
  it('forges a token with the requested subject and scopes', async () => {
    const w = await demoWorld();
    const token = await forgeToken({
      ring: w.ring, clock: w.clock, random: w.random, aud: ['orders'], sub: 'eve', scope: ['orders:write'],
    });
    expect(await w.verifier('orders').verify(token)).toMatchObject({
      ok: true,
      claims: { sub: 'eve', aud: ['orders'], scope: ['orders:write'] },
    });
  });

  it('keeps the original header and signature when tampering', async () => {
    const w = await demoWorld();
    const token = await w.token();
    const [h, , s] = token.split('.');
    const tampered = tamperPayload(token, { sub: 'mallory' }).split('.');
    expect(tampered[0]).toBe(h);
    expect(tampered[2]).toBe(s);
  });

  it('refuses input that is not a compact JWS', () => {
    expect(() => tamperPayload('nope', { a: 1 })).toThrow(/compact JWS/);
  });
});
