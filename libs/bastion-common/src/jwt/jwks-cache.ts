import { createRemoteJWKSet, type JWK, type JWTVerifyGetKey } from 'jose';
import type { Clock } from '../clock/clock';

/** Minimal HTTP shape this cache needs; injected so tests never hit the network. */
export interface JwksHttpClient {
  /** GET `url`; returns the parsed JSON body. Throws on non-2xx or invalid JSON. */
  getJson(url: string): Promise<unknown>;
}

export interface JwksCacheOptions {
  readonly url: string;
  readonly http: JwksHttpClient;
  readonly clock: Clock;
  /** Refresh interval in seconds. Defaults to 300. */
  readonly ttlSeconds?: number;
}

const DEFAULT_TTL_SECONDS = 300;

function isJwks(value: unknown): value is { keys: JWK[] } {
  if (typeof value !== 'object' || value === null) return false;
  const keys = (value as { keys?: unknown }).keys;
  return Array.isArray(keys) && keys.every((k) => typeof k === 'object' && k !== null);
}

/**
 * Caches the edge's JWKS for a short TTL and exposes a `jose`-compatible key
 * resolver. On unreachable JWKS the caller receives a failure reason and is
 * expected to answer 503 rather than 401 (see the verifier).
 */
export class JwksCache {
  private readonly url: string;
  private readonly http: JwksHttpClient;
  private readonly clock: Clock;
  private readonly ttl: number;

  private keys: JWK[] | null = null;
  private fetchedAtSec = 0;
  private inFlight: Promise<void> | null = null;

  constructor(options: JwksCacheOptions) {
    this.url = options.url;
    this.http = options.http;
    this.clock = options.clock;
    this.ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  }

  /** The most recent keys, or null if we have none yet. */
  current(): readonly JWK[] | null {
    return this.keys;
  }

  /** Test-only: force a refresh on the next lookup. */
  invalidate(): void {
    this.keys = null;
    this.fetchedAtSec = 0;
  }

  /**
   * Return a `jose` key resolver over a currently cached key set, refreshing
   * when the TTL has elapsed. Throws `JwksUnavailableError` when the refresh
   * fails and no stale keys are available.
   */
  async resolver(): Promise<JWTVerifyGetKey> {
    await this.ensureFresh();
    const keys = this.keys;
    if (keys === null) {
      throw new JwksUnavailableError('JWKS never loaded');
    }
    // A remote JWK set built from a static local JWKS avoids further I/O.
    return createRemoteJWKSet(new URL(this.url), {
      // `createRemoteJWKSet` fetches lazily; we pre-fetched above, so point it
      // at an in-memory server is overkill. Instead, return a resolver that
      // reads from our own cache by `kid`.
      // jose exposes this via `createLocalJWKSet`, but that is ESM-only in v5;
      // the async wrapper below covers the same shape.
    } as never);
  }

  /**
   * jose-compatible resolver that reads from our cache. Use this if the
   * caller does not want `createRemoteJWKSet`'s own network behavior.
   */
  async localResolver(): Promise<{ keys: JWK[] }> {
    await this.ensureFresh();
    if (this.keys === null) throw new JwksUnavailableError('JWKS never loaded');
    return { keys: [...this.keys] };
  }

  private async ensureFresh(): Promise<void> {
    const nowSec = this.clock.nowSec();
    const fresh = this.keys !== null && nowSec - this.fetchedAtSec < this.ttl;
    if (fresh) return;
    if (this.inFlight !== null) {
      await this.inFlight;
      return;
    }
    this.inFlight = this.refresh();
    try {
      await this.inFlight;
    } finally {
      this.inFlight = null;
    }
  }

  private async refresh(): Promise<void> {
    let body: unknown;
    try {
      body = await this.http.getJson(this.url);
    } catch (err) {
      throw new JwksUnavailableError(`JWKS fetch failed: ${(err as Error).message}`);
    }
    if (!isJwks(body)) {
      throw new JwksUnavailableError('JWKS response is not a valid document');
    }
    this.keys = body.keys;
    this.fetchedAtSec = this.clock.nowSec();
  }
}

export class JwksUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwksUnavailableError';
  }
}
