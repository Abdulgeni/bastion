import * as fc from 'fast-check';
import { ConfigError } from '../errors';
import { CsprngRandom, SeededRandom, createRandomSource } from './random-source';

describe('SeededRandom', () => {
  it('is deterministic for the same seed', () => {
    const a = new SeededRandom('seed-1');
    const b = new SeededRandom('seed-1');
    expect(a.bytes(48).toString('hex')).toBe(b.bytes(48).toString('hex'));
  });

  it('differs across seeds', () => {
    const a = new SeededRandom('seed-1').bytes(32).toString('hex');
    const b = new SeededRandom('seed-2').bytes(32).toString('hex');
    expect(a).not.toBe(b);
  });

  it('does not repeat output on consecutive calls', () => {
    const r = new SeededRandom('seed-1');
    expect(r.bytes(32).equals(r.bytes(32))).toBe(false);
  });

  it('returns exactly the requested length and replays identically (property)', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 200 }), { minLength: 1, maxLength: 8 }),
        fc.string({ minLength: 1 }),
        (lengths, seed) => {
          const a = new SeededRandom(seed);
          const b = new SeededRandom(seed);
          return lengths.every((n) => {
            const x = a.bytes(n);
            return x.length === n && x.equals(b.bytes(n));
          });
        },
      ),
    );
  });
});

describe('CsprngRandom', () => {
  it('returns the requested length and varies', () => {
    const r = new CsprngRandom();
    const x = r.bytes(32);
    expect(x).toHaveLength(32);
    expect(x.equals(r.bytes(32))).toBe(false);
  });

  it.each([0, -1, 1.5, Number.NaN, 65_537])('rejects invalid length %p', (n) => {
    expect(() => new CsprngRandom().bytes(n)).toThrow(RangeError);
    expect(() => new SeededRandom('s').bytes(n)).toThrow(RangeError);
  });
});

describe('createRandomSource', () => {
  it('uses the CSPRNG without a seed', () => {
    expect(createRandomSource({ nodeEnv: 'production' })).toBeInstanceOf(CsprngRandom);
  });

  it('uses the seeded source in test', () => {
    expect(createRandomSource({ nodeEnv: 'test', seed: 'x' })).toBeInstanceOf(SeededRandom);
  });

  it('refuses a seed in production', () => {
    expect(() => createRandomSource({ nodeEnv: 'production', seed: 'x' })).toThrow(ConfigError);
  });
});
