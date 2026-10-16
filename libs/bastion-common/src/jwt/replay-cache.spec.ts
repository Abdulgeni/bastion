import { FakeClock } from '../clock/clock';
import { ReplayCache } from './replay-cache';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const IN_5_MIN = NOW + 300_000;

describe('ReplayCache', () => {
  it('accepts a jti once and reports any second sighting as replayed', () => {
    const cache = new ReplayCache(new FakeClock(NOW));
    expect(cache.consume('orders', 'j1', IN_5_MIN)).toBe('fresh');
    expect(cache.consume('orders', 'j1', IN_5_MIN)).toBe('replayed');
  });

  it('tracks each service independently', () => {
    const cache = new ReplayCache(new FakeClock(NOW));
    expect(cache.consume('orders', 'j1', IN_5_MIN)).toBe('fresh');
    expect(cache.consume('inventory', 'j1', IN_5_MIN)).toBe('fresh');
    expect(cache.consume('payments', 'j1', IN_5_MIN)).toBe('fresh');
  });

  it('forgets a jti once its token has expired', () => {
    const clock = new FakeClock(NOW);
    const cache = new ReplayCache(clock);
    cache.consume('orders', 'j1', IN_5_MIN);
    clock.setMs(IN_5_MIN);
    expect(cache.consume('orders', 'j1', IN_5_MIN + 300_000)).toBe('fresh');
  });

  it('refuses new entries when full instead of evicting a live one', () => {
    const cache = new ReplayCache(new FakeClock(NOW), 2);
    expect(cache.consume('orders', 'j1', IN_5_MIN)).toBe('fresh');
    expect(cache.consume('orders', 'j2', IN_5_MIN)).toBe('fresh');
    expect(cache.consume('orders', 'j3', IN_5_MIN)).toBe('full');
    expect(cache.consume('orders', 'j1', IN_5_MIN)).toBe('replayed');
    expect(cache.size()).toBe(2);
  });

  it('frees room by sweeping expired entries before declaring itself full', () => {
    const clock = new FakeClock(NOW);
    const cache = new ReplayCache(clock, 2);
    cache.consume('orders', 'j1', NOW + 1_000);
    cache.consume('orders', 'j2', NOW + 1_000);
    clock.advanceMs(2_000);
    expect(cache.consume('orders', 'j3', NOW + 400_000)).toBe('fresh');
    expect(cache.size()).toBe(1);
  });

  it.each([0, -1, 1.5, Number.NaN])('rejects maxEntries %p', (n) => {
    expect(() => new ReplayCache(new FakeClock(NOW), n)).toThrow(RangeError);
  });
});
