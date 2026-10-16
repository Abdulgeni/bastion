import { FakeClock } from '../clock/clock';
import { ReplayCache } from './replay-cache';

const NOW = 1_700_000_000;

function setup(capacity?: number, padding?: number) {
  const clock = new FakeClock(NOW * 1000);
  const cache = new ReplayCache(
    clock,
    capacity === undefined ? {} : { capacity, ttlPaddingSeconds: padding },
  );
  return { clock, cache };
}

describe('ReplayCache', () => {
  it('stores a new jti and rejects the second claim', () => {
    const { cache } = setup();
    expect(cache.claim('jti-1', NOW + 300)).toBe('stored');
    expect(cache.claim('jti-1', NOW + 300)).toBe('replayed');
  });

  it('lets different jtis through', () => {
    const { cache } = setup();
    expect(cache.claim('a', NOW + 10)).toBe('stored');
    expect(cache.claim('b', NOW + 10)).toBe('stored');
    expect(cache.size()).toBe(2);
  });

  it('expires entries once the token window plus padding has passed', () => {
    const { cache, clock } = setup(undefined, 30);
    cache.claim('jti-1', NOW + 300);
    clock.setMs((NOW + 300 + 29) * 1000);
    expect(cache.size()).toBe(1);
    clock.setMs((NOW + 300 + 31) * 1000);
    expect(cache.size()).toBe(0);
    expect(cache.claim('jti-1', NOW + 300)).toBe('stored');
  });

  it('denies rather than evicts when full', () => {
    const { cache } = setup(2);
    expect(cache.claim('a', NOW + 300)).toBe('stored');
    expect(cache.claim('b', NOW + 300)).toBe('stored');
    expect(cache.claim('c', NOW + 300)).toBe('too-full');
  });

  it('sweeps before evaluating capacity', () => {
    const { cache, clock } = setup(2, 0);
    cache.claim('a', NOW + 1);
    cache.claim('b', NOW + 1);
    clock.setMs((NOW + 5) * 1000);
    expect(cache.claim('c', NOW + 300)).toBe('stored');
  });
});
