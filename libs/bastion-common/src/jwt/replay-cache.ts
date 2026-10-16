import type { Clock } from '../clock/clock';

interface Entry {
  readonly expiresAt: number;
}

export interface ReplayCacheOptions {
  /** Hard cap on tracked entries. Full cache denies rather than evicting. */
  readonly capacity?: number;
  /** Additional TTL padding in seconds beyond the token's exp. Defaults to 30. */
  readonly ttlPaddingSeconds?: number;
}

const DEFAULT_CAPACITY = 100_000;
const DEFAULT_PADDING = 30;

/** Result of an insert attempt. `tooFull` is a denial signal, not an eviction. */
export type InsertResult = 'stored' | 'replayed' | 'too-full';

/**
 * In-memory single-use tracker for JWT `jti`s, keyed per service.
 *
 * Each service constructs its own cache. A token legitimately arrives at each
 * service once; a second arrival at the same service is a replay. Entries
 * expire `ttlPaddingSeconds` after the token's own `exp`, so a growing cache
 * reflects only tokens whose replay window has not yet closed.
 *
 * A full cache denies (returns `too-full`) rather than evicting, so capacity
 * pressure can never silently re-open a replay.
 */
export class ReplayCache {
  private readonly entries = new Map<string, Entry>();
  private readonly capacity: number;
  private readonly padding: number;
  private readonly clock: Clock;

  constructor(clock: Clock, options: ReplayCacheOptions = {}) {
    this.clock = clock;
    this.capacity = options.capacity ?? DEFAULT_CAPACITY;
    this.padding = options.ttlPaddingSeconds ?? DEFAULT_PADDING;
  }

  /** The number of tracked entries after lazy expiry. Used by tests. */
  size(): number {
    this.sweep();
    return this.entries.size;
  }

  /** Test-only: forget everything. */
  clear(): void {
    this.entries.clear();
  }

  /**
   * Claim `jti` until `exp` + padding. Returns:
   *  - `stored`: newly recorded, safe to proceed.
   *  - `replayed`: already seen, reject with `jwt+replayed`.
   *  - `too-full`: capacity reached after sweeping, reject with 503.
   */
  claim(jti: string, exp: number): InsertResult {
    this.sweep();
    if (this.entries.has(jti)) return 'replayed';
    if (this.entries.size >= this.capacity) return 'too-full';
    this.entries.set(jti, { expiresAt: exp + this.padding });
    return 'stored';
  }

  private sweep(): void {
    const now = this.clock.nowSec();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}
