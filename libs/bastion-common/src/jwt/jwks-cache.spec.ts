import { FakeClock } from '../clock/clock';
import { JwksCache, JwksUnavailableError, type JwksHttpClient } from './jwks-cache';

const NOW = 1_700_000_000;

class FakeHttp implements JwksHttpClient {
  calls = 0;
  response: unknown = { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc', kid: 'k1' }] };
  error: Error | null = null;

  async getJson(_url: string): Promise<unknown> {
    this.calls += 1;
    if (this.error) throw this.error;
    return this.response;
  }
}

function setup(ttlSeconds = 300) {
  const clock = new FakeClock(NOW * 1000);
  const http = new FakeHttp();
  const cache = new JwksCache({ url: 'http://edge/.well-known/jwks.json', http, clock, ttlSeconds });
  return { clock, http, cache };
}

describe('JwksCache', () => {
  it('fetches once and caches within the TTL', async () => {
    const { cache, http } = setup();
    await cache.localResolver();
    await cache.localResolver();
    expect(http.calls).toBe(1);
  });

  it('refetches after the TTL expires', async () => {
    const { cache, http, clock } = setup(10);
    await cache.localResolver();
    clock.setMs((NOW + 5) * 1000);
    await cache.localResolver();
    expect(http.calls).toBe(1);
    clock.setMs((NOW + 11) * 1000);
    await cache.localResolver();
    expect(http.calls).toBe(2);
  });

  it('throws JwksUnavailableError on fetch error', async () => {
    const { cache, http } = setup();
    http.error = new Error('network down');
    await expect(cache.localResolver()).rejects.toThrow(JwksUnavailableError);
  });

  it('throws when the response is not a JWKS', async () => {
    const { cache, http } = setup();
    http.response = { not: 'jwks' };
    await expect(cache.localResolver()).rejects.toThrow(JwksUnavailableError);
  });

  it('invalidate forces a refetch', async () => {
    const { cache, http } = setup();
    await cache.localResolver();
    cache.invalidate();
    await cache.localResolver();
    expect(http.calls).toBe(2);
  });

  it('deduplicates concurrent refreshes', async () => {
    const { cache, http } = setup();
    await Promise.all([cache.localResolver(), cache.localResolver(), cache.localResolver()]);
    expect(http.calls).toBe(1);
  });
});
