import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import { JwtIssuer } from './issuer';
import { JwksCache } from './jwks-cache';
import { generateSigningKey, publicJwks, rotateKeyRing, type KeyRing } from './key-ring';
import { ReplayCache } from './replay-cache';
import { JwtVerifier } from './verifier';

/** 2026-10-12T12:00:00Z, the "now" of every JWT test. */
export const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);

/** A tiny deterministic Bastion: one edge key ring, an in-memory JWKS endpoint, per-service replay caches. */
export function makeWorld(opts: { seed?: string; ring?: KeyRing } = {}) {
  const clock = new FakeClock(NOW);
  const random = new SeededRandom(opts.seed ?? 'jwt-seed');
  let ring =
    opts.ring ?? rotateKeyRing(undefined, generateSigningKey(random, clock.nowMs()), clock.nowMs());
  const state = { fetches: 0, down: false };
  const keys = new JwksCache({
    clock,
    fetch: async () => {
      state.fetches += 1;
      if (state.down) throw new Error('edge is down');
      return JSON.stringify(publicJwks(ring, clock.nowMs()));
    },
  });
  const issuer = new JwtIssuer({ ring: () => ring, clock, random });
  const replays = new Map<string, ReplayCache>();
  const replayFor = (service: string): ReplayCache => {
    const cache = replays.get(service) ?? new ReplayCache(clock);
    replays.set(service, cache);
    return cache;
  };
  return {
    clock,
    random,
    state,
    keys,
    issuer,
    replayFor,
    get ring(): KeyRing {
      return ring;
    },
    rotate(): void {
      ring = rotateKeyRing(ring, generateSigningKey(random, clock.nowMs()), clock.nowMs());
    },
    /** A verifier for `service`, or edge's non-consuming verifier when omitted. */
    verifier(service?: string): JwtVerifier {
      const replayCache = service ? replayFor(service) : undefined;
      return new JwtVerifier({ keys, clock, service, replayCache });
    },
    async token(): Promise<string> {
      const scope = ['orders:write', 'inventory:reserve', 'payments:charge'] as const;
      return (await issuer.issue({ sub: 'alice', scope })).token;
    },
  };
}
