import * as fc from 'fast-check';
import { ISSUER, isValidSubject, parseClaims } from './claims';

const valid = {
  iss: ISSUER,
  sub: 'alice',
  aud: ['orders', 'inventory', 'payments'],
  iat: 1_000,
  exp: 1_300,
  jti: 'a'.repeat(32),
  scope: ['orders:write'],
};

describe('parseClaims', () => {
  it('accepts a well-formed payload and ignores extra fields', () => {
    expect(parseClaims(valid)).toEqual(valid);
    expect(parseClaims({ ...valid, admin: true })).toEqual(valid);
  });

  it.each([[null], [undefined], [5], ['x'], [[]], [[valid]]])('rejects the non-object %p', (v) => {
    expect(parseClaims(v)).toBeUndefined();
  });

  it.each([
    ['missing iss', { iss: undefined }],
    ['empty sub', { sub: '' }],
    ['sub with a space', { sub: 'a b' }],
    ['sub too long', { sub: 'a'.repeat(65) }],
    ['numeric sub', { sub: 7 }],
    ['empty aud', { aud: [] }],
    ['string aud', { aud: 'orders' }],
    ['aud with uppercase', { aud: ['Orders'] }],
    ['aud with a number', { aud: [1] }],
    ['too many aud entries', { aud: Array.from({ length: 17 }, () => 'orders') }],
    ['short jti', { jti: 'abc' }],
    ['uppercase jti', { jti: 'A'.repeat(32) }],
    ['string scope', { scope: 'orders:write' }],
    ['empty scope', { scope: [] }],
    ['fractional iat', { iat: 1.5 }],
    ['string exp', { exp: '1300' }],
    ['negative iat', { iat: -1 }],
    ['NaN exp', { exp: Number.NaN }],
    ['missing exp', { exp: undefined }],
  ])('rejects %s', (_name, patch) => {
    expect(parseClaims({ ...valid, ...patch })).toBeUndefined();
  });

  it('never throws, whatever it is given (fuzz)', () => {
    fc.assert(
      fc.property(fc.anything(), (v) => {
        parseClaims(v);
        return true;
      }),
    );
  });
});

describe('isValidSubject', () => {
  it.each([['alice', true], ['a.b-c_d@e', true], ['', false], ['a/b', false], [5, false]])(
    '%p -> %p',
    (v, expected) => {
      expect(isValidSubject(v)).toBe(expected);
    },
  );
});
