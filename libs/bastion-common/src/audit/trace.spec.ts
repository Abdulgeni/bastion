import { SeededRandom } from '../random/random-source';
import { describeResource, resourceLabel } from './resource';
import { resolveTraceId } from './trace';

describe('resolveTraceId', () => {
  const random = () => new SeededRandom('trace');

  it('reuses a well-formed incoming ID, including from an array header', () => {
    expect(resolveTraceId('0123456789abcdef', random())).toBe('0123456789abcdef');
    expect(resolveTraceId(['0123456789abcdef', 'ffffffffffffffff'], random())).toBe('0123456789abcdef');
  });

  it.each([
    undefined, '', 'ABCDEF0123456789', '0123456789abcde', '0123456789abcdef0', 'abc\r\nX: 1', 'zzzzzzzzzzzzzzzz',
  ])('replaces the bad value %p with a fresh 16-hex ID', (header) => {
    expect(resolveTraceId(header, random())).toMatch(/^[0-9a-f]{16}$/);
  });

  it('generates reproducibly from a seeded source', () => {
    expect(resolveTraceId(undefined, random())).toBe(resolveTraceId(undefined, random()));
  });
});

describe('describeResource and resourceLabel', () => {
  it('uses the route template, not the concrete URL', () => {
    expect(describeResource({ method: 'GET', url: '/orders/42?x=1', route: { path: '/orders/:id' } })).toBe('GET /orders/:id');
  });

  it('falls back to the path without the query string', () => {
    expect(describeResource({ method: 'POST', url: '/charge?x=1' })).toBe('POST /charge');
    expect(describeResource({})).toBe('UNKNOWN ');
  });

  it.each([['POST /charge', 'POST /charge'], ['GET /orders/:id', 'GET /orders/:id']])('keeps %s', (r, label) => {
    expect(resourceLabel(r)).toBe(label);
  });

  it.each(['get /charge', 'GET /a b', `GET /${'a'.repeat(200)}`, 'GET /x"y', 'GET charge'])(
    'maps %p to other',
    (r) => {
      expect(resourceLabel(r)).toBe('other');
    },
  );
});
