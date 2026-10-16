import { CompactSign } from 'jose';
import { ISSUER, type BastionClaims } from './claims';
import { signClaims } from './issuer';
import { activeKey, generateSigningKey } from './key-ring';
import { ReplayCache } from './replay-cache';
import { JwtVerifier, checkScope, extractBearerToken } from './verifier';
import { NOW, makeWorld } from './test-helpers';

type World = ReturnType<typeof makeWorld>;
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function claims(w: World, over: Partial<BastionClaims> = {}): BastionClaims {
  const iat = w.clock.nowSec();
  return {
    iss: ISSUER,
    sub: 'alice',
    aud: ['orders', 'inventory', 'payments'],
    iat,
    exp: iat + 300,
    jti: w.random.bytes(16).toString('hex'),
    scope: ['orders:write'],
    ...over,
  };
}

const sign = (w: World, c: BastionClaims) => signClaims(activeKey(w.ring), c);

describe('JwtVerifier: happy path and replay', () => {
  it('accepts a valid token and reports the kid and claims', async () => {
    const w = makeWorld();
    const r = await w.verifier('orders').verify(await w.token());
    expect(r).toMatchObject({ ok: true, kid: w.ring.active, claims: { sub: 'alice' } });
  });

  it('rejects the second presentation to the same service as replayed', async () => {
    const w = makeWorld();
    const token = await w.token();
    const orders = w.verifier('orders');
    expect((await orders.verify(token)).ok).toBe(true);
    expect(await orders.verify(token)).toMatchObject({
      ok: false,
      reason: 'jwt+replayed',
      status: 401,
      claims: { sub: 'alice' },
    });
  });

  it('lets one token pass through each service exactly once', async () => {
    const w = makeWorld();
    const token = await w.token();
    for (const service of ['orders', 'inventory', 'payments']) {
      expect((await w.verifier(service).verify(token)).ok).toBe(true);
    }
    expect((await w.verifier('inventory').verify(token)).ok).toBe(false);
  });

  it('answers 503 replay+cache_full instead of evicting when the cache is full', async () => {
    const w = makeWorld();
    const verifier = new JwtVerifier({
      keys: w.keys,
      clock: w.clock,
      service: 'orders',
      replayCache: new ReplayCache(w.clock, 1),
    });
    expect((await verifier.verify(await w.token())).ok).toBe(true);
    expect(await verifier.verify(await w.token())).toMatchObject({
      reason: 'replay+cache_full',
      status: 503,
    });
  });

  it('refuses a replay cache without a service name', () => {
    const w = makeWorld();
    expect(() => new JwtVerifier({ keys: w.keys, clock: w.clock, replayCache: new ReplayCache(w.clock) })).toThrow(RangeError);
  });
});

describe('JwtVerifier: expiry and audience', () => {
  it('expires a token exactly at exp, and does not consume its jti', async () => {
    const w = makeWorld();
    const early = await w.token();
    const late = await w.token();
    w.clock.advanceMs(299_000);
    expect((await w.verifier('orders').verify(early)).ok).toBe(true);
    w.clock.advanceMs(1_000);
    expect(await w.verifier('orders').verify(late)).toMatchObject({ reason: 'jwt+expired', status: 401 });
    expect(w.replayFor('orders').size()).toBe(1);
  });

  it('rejects a genuinely signed token whose audience excludes this service', async () => {
    const w = makeWorld();
    const token = await sign(w, claims(w, { aud: ['payments'] }));
    expect(await w.verifier('orders').verify(token)).toMatchObject({
      reason: 'jwt+bad_aud',
      status: 401,
      claims: { aud: ['payments'] },
    });
    expect(w.replayFor('orders').size()).toBe(0);
    expect((await w.verifier('payments').verify(token)).ok).toBe(true);
  });

  it('lets edge verify without checking audience or consuming the jti', async () => {
    const w = makeWorld();
    const token = await sign(w, claims(w, { aud: ['payments'] }));
    const edge = w.verifier();
    expect((await edge.verify(token)).ok).toBe(true);
    expect((await edge.verify(token)).ok).toBe(true);
    w.clock.advanceMs(300_000);
    expect(await edge.verify(token)).toMatchObject({ reason: 'jwt+expired' });
  });
});

describe('JwtVerifier: signatures', () => {
  it('rejects a payload edited after signing', async () => {
    const w = makeWorld();
    const [h, p, s] = (await w.token()).split('.');
    const edited = { ...JSON.parse(Buffer.from(p as string, 'base64url').toString()), sub: 'mallory' };
    const result = await w.verifier('orders').verify(`${h}.${b64(edited)}.${s}`);
    expect(result).toMatchObject({ reason: 'jwt+bad_sig', status: 401 });
    expect('claims' in result).toBe(false);
  });

  it('rejects a token signed by a key edge never published', async () => {
    const w = makeWorld();
    const stranger = generateSigningKey(w.random, NOW);
    expect(await w.verifier('orders').verify(await signClaims(stranger, claims(w)))).toMatchObject({
      reason: 'jwt+bad_sig',
    });
  });

  it('rejects algorithm "none" and HS256 confusion attempts', async () => {
    const w = makeWorld();
    const body = b64(claims(w));
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${body}.`;
    const hs = `${b64({ alg: 'HS256', typ: 'JWT', kid: w.ring.active })}.${body}.${b64('x')}`;
    for (const token of [none, hs]) {
      expect(await w.verifier('orders').verify(token)).toMatchObject({ reason: 'jwt+bad_sig' });
    }
  });
});

describe('JwtVerifier: malformed input', () => {
  it.each([
    ['empty', ''],
    ['one segment', 'abc'],
    ['two segments', 'a.b'],
    ['three junk segments', 'a.b.c'],
    ['only dots', '...'],
    ['oversized', 'x'.repeat(5000)],
  ])('answers jwt+malformed for %s', async (_name, token) => {
    const w = makeWorld();
    expect(await w.verifier('orders').verify(token)).toMatchObject({ reason: 'jwt+malformed', status: 401 });
  });

  async function signedPayload(w: World, payload: Uint8Array): Promise<string> {
    return new CompactSign(payload)
      .setProtectedHeader({ alg: 'EdDSA', kid: w.ring.active })
      .sign(activeKey(w.ring).privateKey);
  }

  it('rejects correctly signed payloads that are not valid claims', async () => {
    const w = makeWorld();
    const enc = (s: string) => new TextEncoder().encode(s);
    for (const bytes of [enc('not json'), enc('[]'), enc('{"sub":"alice"}'), enc('null')]) {
      expect(await w.verifier('orders').verify(await signedPayload(w, bytes))).toMatchObject({
        reason: 'jwt+malformed',
      });
    }
  });

  it('enforces issuer, maximum lifetime and sane iat on correctly signed claims', async () => {
    const w = makeWorld();
    const now = w.clock.nowSec();
    const bad: Partial<BastionClaims>[] = [
      { iss: 'evil' },
      { exp: now + 301 },
      { exp: now },
      { iat: now + 61, exp: now + 120 },
    ];
    for (const over of bad) {
      expect(await w.verifier('orders').verify(await sign(w, claims(w, over)))).toMatchObject({
        reason: 'jwt+malformed',
      });
    }
    const past = await sign(w, claims(w, { iat: now - 5, exp: now - 1 }));
    expect(await w.verifier('orders').verify(past)).toMatchObject({ reason: 'jwt+expired' });
  });
});

describe('JwtVerifier: JWKS availability', () => {
  it('answers 503 jwks+unavailable while edge is unreachable, and recovers', async () => {
    const w = makeWorld();
    const token = await w.token();
    w.state.down = true;
    expect(await w.verifier('orders').verify(token)).toMatchObject({
      ok: false,
      reason: 'jwks+unavailable',
      status: 503,
    });
    w.state.down = false;
    w.clock.advanceMs(1_000);
    expect((await w.verifier('orders').verify(token)).ok).toBe(true);
  });
});

describe('JwtVerifier: key rotation', () => {
  it('keeps accepting tokens signed by the retired key and accepts the new key after a refetch', async () => {
    const w = makeWorld();
    const oldToken = await w.token();
    const oldKid = w.ring.active;
    expect((await w.verifier('orders').verify(await w.token())).ok).toBe(true);

    w.rotate();
    const newToken = await w.token();
    w.clock.advanceMs(1_000);

    expect(w.ring.active).not.toBe(oldKid);
    expect(await w.verifier('orders').verify(oldToken)).toMatchObject({ ok: true, kid: oldKid });
    expect(await w.verifier('orders').verify(newToken)).toMatchObject({
      ok: true,
      kid: w.ring.active,
    });
  });

  it('rejects a brand-new key inside the miss cooldown (documented one-second window)', async () => {
    const w = makeWorld();
    expect((await w.verifier('orders').verify(await w.token())).ok).toBe(true);
    w.rotate();
    expect(await w.verifier('orders').verify(await w.token())).toMatchObject({ reason: 'jwt+bad_sig' });
    w.clock.advanceMs(1_000);
    expect((await w.verifier('orders').verify(await w.token())).ok).toBe(true);
  });
});

describe('checkScope', () => {
  const c = claims(makeWorld(), { scope: ['orders:write'] });

  it('passes when the scope is present', () => {
    expect(checkScope(c, 'orders:write')).toEqual({ ok: true });
  });

  it('fails with 403 and the audit reason naming the missing scope', () => {
    expect(checkScope(c, 'payments:charge')).toEqual({
      ok: false,
      reason: 'scope+missing:payments:charge',
      status: 403,
    });
  });
});

describe('extractBearerToken', () => {
  const jwt = 'aaa.bbb.ccc';

  it('extracts a well-formed bearer token', () => {
    expect(extractBearerToken(`Bearer ${jwt}`)).toBe(jwt);
  });

  it.each([
    undefined,
    '',
    'Bearer',
    'Bearer ',
    `bearer ${jwt}`,
    `Basic ${jwt}`,
    `Bearer ${jwt} extra`,
    'Bearer a.b',
    'Bearer a.b.c.d',
    'Bearer a.b.c\nX-Injected: 1',
    `Bearer ${'x'.repeat(5000)}.b.c`,
  ])('rejects %p', (header) => {
    expect(extractBearerToken(header)).toBeUndefined();
  });
});
