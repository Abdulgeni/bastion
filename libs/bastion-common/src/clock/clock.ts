/** Source of "now" for every time-dependent decision in Bastion (JWT exp, cert validity, audit ts, TTLs). */
export interface Clock {
  /** Epoch milliseconds. */
  nowMs(): number;
  /** The current instant as a Date. */
  now(): Date;
  /** Epoch seconds, rounded down (the unit JWT `exp` and `iat` use). */
  nowSec(): number;
}

/** Real wall-clock time. The only Clock used outside tests. */
export class SystemClock implements Clock {
  nowMs(): number {
    return Date.now();
  }

  now(): Date {
    return new Date(this.nowMs());
  }

  nowSec(): number {
    return Math.floor(this.nowMs() / 1000);
  }
}

function assertFinite(ms: number): number {
  if (!Number.isFinite(ms)) {
    throw new RangeError('FakeClock time must be a finite number of milliseconds');
  }
  return ms;
}

/** Manually controlled clock so tests can move time without Jest fake timers. */
export class FakeClock implements Clock {
  private ms: number;

  constructor(startMs: number) {
    this.ms = assertFinite(startMs);
  }

  nowMs(): number {
    return this.ms;
  }

  now(): Date {
    return new Date(this.ms);
  }

  nowSec(): number {
    return Math.floor(this.ms / 1000);
  }

  /** Move time by `deltaMs` (negative values simulate clock skew). */
  advanceMs(deltaMs: number): void {
    this.ms += assertFinite(deltaMs);
  }

  /** Jump to an absolute time. */
  setMs(ms: number): void {
    this.ms = assertFinite(ms);
  }
}
