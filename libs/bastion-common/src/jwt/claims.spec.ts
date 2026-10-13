import { FakeClock } from '../clock/clock';
import { validateClaims } from './claims';
import { JWT_REASON } from './reasons';

const NOW = 1_700_000_000;
const AUD = 'orders';
const ISS = 'edge';

function clock(at = NOW) {
  return new FakeClock(at * 1000);
}

function good(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'alice',
    aud: [AUD],
    iss: ISS,
    iat: NOW - 5,
    exp: NOW + 300,
    jti: 'jti-1',
    scope: ['orders:write'],
    ...over,
  };
}

function run(payload: Record<string, unknown>, at = NOW) {
  return validateClaims(payload, {
    expectedAudience: AUD,
    expectedIssuer: ISS,
    clock: clock(at),
  });
}

describe('validateClaims', () => {
  it('accepts a well-formed token', () => {
    const r = run(good());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.claims.sub).toBe('alice');
      expect(r.claims.aud).toEqual([AUD]);
      expect(r.claims.scope).toEqual(['orders:write']);
    }
  });

  it.each([
    ['sub missing', { sub: undefined }, 'sub'],
    ['sub empty', { sub: '' }, 'sub'],
    ['jti missing', { jti: undefined }, 'jti'],
    ['exp not a number', { exp: 'soon' }, 'exp'],
    ['iat not a number', { iat: null }, 'iat'],
    ['iss not a string', { iss: 42 }, 'iss'],
    ['aud not an array', { aud: AUD }, 'aud'],
    ['aud empty', { aud: [] }, 'aud'],
    ['scope not an array', { scope: 'orders:write' }, 'scope'],
  ])('rejects %s', (_name, over, detail) => {
    const r = run(good(over));
    expect(r).toMatchObject({ ok: false, reason: JWT_REASON.MALFORMED, detail });
  });

  it('reports expired when now is past exp', () => {
    const r = run(good(), NOW + 400);
    expect(r).toMatchObject({ ok: false, reason: JWT_REASON.EXPIRED });
  });

  it('treats exp as exclusive', () => {
    expect(run(good({ exp: NOW }), NOW)).toMatchObject({
      ok: false,
      reason: JWT_REASON.EXPIRED,
    });
  });

  it('reports not-yet-valid when now is before iat', () => {
    const r = run(good({ iat: NOW + 60 }), NOW);
    expect(r).toMatchObject({ ok: false, reason: JWT_REASON.NOT_YET_VALID });
  });

  it('reports bad issuer', () => {
    const r = run(good({ iss: 'somewhere-else' }));
    expect(r).toMatchObject({ ok: false, reason: JWT_REASON.BAD_ISSUER });
  });

  it('reports bad audience when our service is not in aud', () => {
    const r = run(good({ aud: ['payments'] }));
    expect(r).toMatchObject({ ok: false, reason: JWT_REASON.BAD_AUD });
  });

  it('accepts a token whose aud contains several services', () => {
    const r = run(good({ aud: ['orders', 'inventory', 'payments'] }));
    expect(r.ok).toBe(true);
  });

  it('uses the Clock, not the real time', () => {
    // A token whose window is ancient (year 2001). If validation consulted the
    // real time it would be expired; using the Clock in the same window succeeds.
    const ancient = 1_000_000_000;
    const token = {
      sub: 'alice',
      aud: [AUD],
      iss: ISS,
      iat: ancient - 5,
      exp: ancient + 300,
      jti: 'jti-ancient',
      scope: ['orders:write'],
    };
    const r = run(token, ancient);
    expect(r.ok).toBe(true);
  });
});
