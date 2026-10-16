import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import {
  JwksCache,
  JwksUnavailableError,
  UnknownKeyError,
  httpJwksFetcher,
  parseJwks,
} from './jwks-cache';
import { generateSigningKey, publicJwks, rotateKeyRing, type KeyRing } from './key-ring';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);

function setup() {
  const clock = new FakeClock(NOW);
  const random = new SeededRandom('jwks');
  let ring: KeyRing = rotateKeyRing(undefined, generateSigningKey(random, NOW), NOW);
  const state = { fetches: 0, fail: false, body: undefined as string | undefined };
  const cache = new JwksCache({
    clock,
    fetch: async () => {
      state.fetches += 1;
      if (state.fail) throw new Error('boom');
      return state.body ?? JSON.stringify(publicJwks(ring, clock.nowMs()));
    },
  });
  return {
    clock,
    state,
    cache,
    kid: () => ring.active,
    rotate: () => {
      ring = rotateKeyRing(ring, generateSigningKey(random, clock.nowMs()), clock.nowMs());
    },
  };
}

describe('JwksCache', () => {
  it('fetches once and serves from cache within the TTL', async () => {
    const w = setup();
    for (let i = 0; i < 3; i++) await w.cache.keyFor(w.kid());
    expect(w.state.fetches).toBe(1);
  });

  it('refetches after the TTL', async () => {
    const w = setup();
    await w.cache.keyFor(w.kid());
    w.clock.advanceMs(30_000);
    await w.cache.keyFor(w.kid());
    expect(w.state.fetches).toBe(2);
  });

  it('shares one fetch between concurrent callers', async () => {
    const w = setup();
    await Promise.all([w.cache.keyFor(w.kid()), w.cache.keyFor(w.kid()), w.cache.keyFor(w.kid())]);
    expect(w.state.fetches).toBe(1);
  });

  it('rejects an unknown kid, refetching only after the miss cooldown', async () => {
    const w = setup();
    await w.cache.keyFor(w.kid());
    await expect(w.cache.keyFor('nope')).rejects.toThrow(UnknownKeyError);
    expect(w.state.fetches).toBe(1);
    w.clock.advanceMs(1_000);
    await expect(w.cache.keyFor('nope')).rejects.toThrow(UnknownKeyError);
    expect(w.state.fetches).toBe(2);
  });

  it('picks up a rotated key through the miss refetch', async () => {
    const w = setup();
    const oldKid = w.kid();
    await w.cache.keyFor(oldKid);
    w.rotate();
    w.clock.advanceMs(1_000);
    expect(await w.cache.keyFor(w.kid())).toBeDefined();
    expect(await w.cache.keyFor(oldKid)).toBeDefined();
  });

  it('rejects a missing kid', async () => {
    await expect(setup().cache.keyFor(undefined)).rejects.toThrow(UnknownKeyError);
  });

  it('fails fast during the failure cooldown, then recovers', async () => {
    const w = setup();
    w.state.fail = true;
    await expect(w.cache.keyFor(w.kid())).rejects.toThrow(JwksUnavailableError);
    await expect(w.cache.keyFor(w.kid())).rejects.toThrow(JwksUnavailableError);
    expect(w.state.fetches).toBe(1);
    w.state.fail = false;
    w.clock.advanceMs(1_000);
    expect(await w.cache.keyFor(w.kid())).toBeDefined();
  });

  it('never serves stale keys when a refresh fails after the TTL', async () => {
    const w = setup();
    await w.cache.keyFor(w.kid());
    w.state.fail = true;
    w.clock.advanceMs(30_000);
    await expect(w.cache.keyFor(w.kid())).rejects.toThrow(JwksUnavailableError);
  });

  it.each([
    ['not JSON', 'nope'],
    ['no keys member', '{}'],
    ['empty keys', '{"keys":[]}'],
    ['an RSA key', JSON.stringify({ keys: [{ kty: 'RSA', n: 'x', e: 'AQAB', kid: 'k' }] })],
    ['a short x', JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc', kid: 'k' }] })],
    ['a bad kid', JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43), kid: 'bad kid!' }] })],
    ['too many keys', JSON.stringify({ keys: Array.from({ length: 11 }, (_, i) => ({ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43), kid: `k${i}` })) })],
  ])('treats %s as unavailable', async (_name, body) => {
    const w = setup();
    w.state.body = body;
    await expect(w.cache.keyFor('k')).rejects.toThrow(JwksUnavailableError);
  });
});

describe('parseJwks', () => {
  it('accepts a document produced by publicJwks', () => {
    const ring = rotateKeyRing(undefined, generateSigningKey(new SeededRandom('p'), NOW), NOW);
    expect(parseJwks(JSON.stringify(publicJwks(ring, NOW))).has(ring.active)).toBe(true);
  });
});

describe('httpJwksFetcher', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/ok') res.end('{"keys":[]}');
      else if (req.url === '/500') res.writeHead(500).end('no');
      else if (req.url === '/big') res.end('x'.repeat(70_000));
      else if (req.url === '/redirect') res.writeHead(302, { location: '/ok' }).end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  it('returns the body of a 200 response', async () => {
    expect(await httpJwksFetcher(`${base}/ok`)()).toBe('{"keys":[]}');
  });

  it.each([['/500', /500/], ['/big', /too large/]])('rejects %s', async (path, pattern) => {
    await expect(httpJwksFetcher(`${base}${path}`)()).rejects.toThrow(pattern);
  });

  it('refuses redirects and times out on a silent server', async () => {
    await expect(httpJwksFetcher(`${base}/redirect`)()).rejects.toThrow();
    await expect(httpJwksFetcher(`${base}/silent`, 150)()).rejects.toThrow();
  });

  it('rejects non-http URLs up front', () => {
    expect(() => httpJwksFetcher('ftp://x/jwks')).toThrow(RangeError);
  });
});
