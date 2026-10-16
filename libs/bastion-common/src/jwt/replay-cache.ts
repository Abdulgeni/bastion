import type { Clock } from '../clock/clock';

/** `fresh`: first sighting, now recorded. `replayed`: seen before. `full`: no room to record it. */
export type ConsumeResult = 'fresh' | 'replayed' | 'full';

/**
 * In-process record of used `(service, jti)` pairs. Entries live until the token's own
 * `exp`, after which the token is rejected as expired anyway, so forgetting them is safe.
 * When full it refuses (fail closed) rather than evicting a live entry, because eviction
 * would silently re-open replay for that token.
 */
export class ReplayCache {
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly clock: Clock,
    private readonly maxEntries = 10_000,
  ) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('maxEntries must be a positive integer');
    }
  }

  /** Records the jti if unseen. `expiresAtMs` is the token's `exp` in milliseconds. */
  consume(service: string, jti: string, expiresAtMs: number): ConsumeResult {
    const now = this.clock.nowMs();
    const key = `${service}:${jti}`;
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) return 'replayed';
    if (this.seen.size >= this.maxEntries) this.sweep(now);
    if (this.seen.size >= this.maxEntries && existing === undefined) return 'full';
    this.seen.set(key, expiresAtMs);
    return 'fresh';
  }

  /** Number of entries currently held (expired ones may linger until the next sweep). */
  size(): number {
    return this.seen.size;
  }

  private sweep(now: number): void {
    for (const [key, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(key);
    }
  }
}
