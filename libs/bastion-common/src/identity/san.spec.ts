import { extractUriSans } from './san';

describe('extractUriSans', () => {
  it('extracts the URI from a typical SAN string', () => {
    expect(extractUriSans('DNS:edge, URI:spiffe://bastion.local/services/edge')).toEqual([
      'spiffe://bastion.local/services/edge',
    ]);
  });

  it.each([undefined, '', 'DNS:edge', 'IP Address:10.0.0.1'])('finds nothing in %p', (san) => {
    expect(extractUriSans(san)).toEqual([]);
  });

  it('returns every URI when there are several', () => {
    expect(extractUriSans('URI:spiffe://a.b/services/x, URI:spiffe://a.b/services/y')).toEqual([
      'spiffe://a.b/services/x',
      'spiffe://a.b/services/y',
    ]);
  });

  it('decodes quoted values', () => {
    expect(extractUriSans('URI:"spiffe://a.b/services/x"')).toEqual(['spiffe://a.b/services/x']);
  });

  it('is not fooled by "URI:" text inside a quoted DNS entry', () => {
    const san = 'DNS:"x, URI:spiffe://bastion.local/services/edge"';
    expect(extractUriSans(san)).toEqual([]);
  });

  it('handles escaped quotes before a real URI entry', () => {
    const san = 'DNS:"a\\"b", URI:spiffe://bastion.local/services/edge';
    expect(extractUriSans(san)).toEqual(['spiffe://bastion.local/services/edge']);
  });

  it('ignores malformed quoted values instead of throwing', () => {
    expect(extractUriSans('URI:"unterminated')).toEqual([]);
  });
});
