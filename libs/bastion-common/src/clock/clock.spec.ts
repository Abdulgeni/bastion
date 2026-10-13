import { FakeClock, SystemClock } from './clock';

describe('SystemClock', () => {
  it('tracks real time', () => {
    const before = Date.now();
    const t = new SystemClock().nowMs();
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(Date.now());
  });
});

describe('FakeClock', () => {
  it('stays put until moved', () => {
    const clock = new FakeClock(1_000);
    expect(clock.nowMs()).toBe(1_000);
    expect(clock.nowMs()).toBe(1_000);
  });

  it('advances and jumps', () => {
    const clock = new FakeClock(0);
    clock.advanceMs(5_000);
    expect(clock.nowMs()).toBe(5_000);
    clock.setMs(42);
    expect(clock.nowMs()).toBe(42);
  });

  it('supports moving backwards to simulate skew', () => {
    const clock = new FakeClock(10_000);
    clock.advanceMs(-4_000);
    expect(clock.nowMs()).toBe(6_000);
  });

  it('floors seconds', () => {
    expect(new FakeClock(1_999).nowSec()).toBe(1);
    expect(new FakeClock(2_000).nowSec()).toBe(2);
  });

  it('returns a Date for the same instant', () => {
    expect(new FakeClock(86_400_000).now().toISOString()).toBe('1970-01-02T00:00:00.000Z');
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY])('rejects non-finite value %p', (bad) => {
    expect(() => new FakeClock(bad)).toThrow(RangeError);
    const clock = new FakeClock(0);
    expect(() => clock.advanceMs(bad)).toThrow(RangeError);
    expect(() => clock.setMs(bad)).toThrow(RangeError);
  });
});
