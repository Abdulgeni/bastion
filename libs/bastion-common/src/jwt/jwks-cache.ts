import { createPublicKey, type KeyObject } from 'node:crypto';
import type { Clock } from '../clock/clock';

const MAX_KEYS = 10;
const KID = /^[A-Za-z0-9_-]{1,64}$/;
const X = /^[A-Za-z0-9_-]{43}$/;

/** The JWKS could not be fetched or was invalid: callers answer 503 `jwks+unavailable`. */
export class JwksUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwksUnavailableError';
  }
}

/** The token names a key we do not have (after refreshing): treated as a bad signature. */
export class UnknownKeyError extends Error {
  constructor() {
    super('no matching key');
    this.name = 'UnknownKeyError';
  }
}

/** Anything that can turn a token's `kid` into a public key. */
export interface KeySource {
  keyFor(kid: string | undefined): Promise<KeyObject>;
}

export interface JwksCacheOptions {
  /** Returns the raw JWKS JSON text, or rejects. */
  readonly fetch: () => Promise<string>;
  readonly clock: Clock;
  /** How long a fetched JWKS is used before refetching (default 30 s). */
  readonly ttlMs?: number;
  /** Minimum age of the cached JWKS before an unknown `kid` triggers a refetch (default 1 s). */
  readonly missCooldownMs?: number;
  /** After a failed fetch, fail fast for this long instead of retrying (default 1 s). */
  readonly failureCooldownMs?: number;
}

/** Parses an untrusted JWKS document. Anything unexpected invalidates the whole document. */
export function parseJwks(text: string): Map<string, KeyObject> {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new JwksUnavailableError('JWKS is not valid JSON');
  }
  const list = (doc as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_KEYS) {
    throw new JwksUnavailableError('JWKS has an unexpected number of keys');
  }
  const keys = new Map<string, KeyObject>();
  for (const entry of list as Record<string, unknown>[]) {
    const ok = entry?.kty === 'OKP' && entry.crv === 'Ed25519' && X.test(String(entry.x)) && KID.test(String(entry.kid));
    if (!ok) throw new JwksUnavailableError('JWKS contains an unsupported key');
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: String(entry.x) };
    keys.set(String(entry.kid), createPublicKey({ key: jwk, format: 'jwk' }));
  }
  return keys;
}

/**
 * Caches edge's JWKS. Stale keys are never served: once the TTL passes, a failed refresh
 * means `JwksUnavailableError`. Concurrent callers share one fetch.
 */
export class JwksCache implements KeySource {
  private keys = new Map<string, KeyObject>();
  private fetchedAt: number | undefined;
  private failedAt: number | undefined;
  private inflight: Promise<void> | undefined;
  private readonly ttlMs: number;
  private readonly missCooldownMs: number;
  private readonly failureCooldownMs: number;

  constructor(private readonly opts: JwksCacheOptions) {
    this.ttlMs = opts.ttlMs ?? 30_000;
    this.missCooldownMs = opts.missCooldownMs ?? 1_000;
    this.failureCooldownMs = opts.failureCooldownMs ?? 1_000;
  }

  async keyFor(kid: string | undefined): Promise<KeyObject> {
    if (kid === undefined) throw new UnknownKeyError();
    if (this.isStale()) await this.refresh();
    let key = this.keys.get(kid);
    if (!key && this.canRefreshOnMiss()) {
      await this.refresh();
      key = this.keys.get(kid);
    }
    if (!key) throw new UnknownKeyError();
    return key;
  }

  private isStale(): boolean {
    return this.fetchedAt === undefined || this.opts.clock.nowMs() - this.fetchedAt >= this.ttlMs;
  }

  private canRefreshOnMiss(): boolean {
    return this.fetchedAt !== undefined && this.opts.clock.nowMs() - this.fetchedAt >= this.missCooldownMs;
  }

  private refresh(): Promise<void> {
    this.inflight ??= this.doRefresh().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private async doRefresh(): Promise<void> {
    const now = this.opts.clock.nowMs();
    if (this.failedAt !== undefined && now - this.failedAt < this.failureCooldownMs) {
      throw new JwksUnavailableError('JWKS fetch failed recently');
    }
    try {
      this.keys = parseJwks(await this.opts.fetch());
      this.fetchedAt = this.opts.clock.nowMs();
      this.failedAt = undefined;
    } catch (err) {
      this.failedAt = this.opts.clock.nowMs();
      this.fetchedAt = undefined;
      this.keys = new Map();
      throw err instanceof JwksUnavailableError ? err : new JwksUnavailableError('JWKS fetch failed');
    }
  }
}

/** A fetcher for an http(s) JWKS URL: bounded time and size, no redirects. */
export function httpJwksFetcher(url: string, timeoutMs = 2_000, maxBytes = 65_536): () => Promise<string> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new RangeError('JWKS URL must be http or https');
  }
  return async () => {
    const res = await fetch(parsed, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
    if (!res.ok) throw new Error(`JWKS endpoint returned ${res.status}`);
    const body = Buffer.from(await res.arrayBuffer());
    if (body.length > maxBytes) throw new Error('JWKS response too large');
    return body.toString('utf8');
  };
}
