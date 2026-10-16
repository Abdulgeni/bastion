import { compactVerify } from 'jose';
import type { Clock } from '../clock/clock';
import { ISSUER, TOKEN_TTL_SECONDS, parseClaims, type BastionClaims, type Scope } from './claims';
import { JwksUnavailableError, UnknownKeyError, type KeySource } from './jwks-cache';
import { JWT_REASON, scopeMissingReason, type JwtReason } from './reasons';
import type { ReplayCache } from './replay-cache';

const MAX_TOKEN_LENGTH = 4096;
const MAX_FUTURE_IAT_SECONDS = 60;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const SIGNATURE_CODES: ReadonlySet<string> = new Set([
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  'ERR_JOSE_ALG_NOT_ALLOWED',
]);

export type JwtResult =
  | { readonly ok: true; readonly claims: BastionClaims; readonly kid: string }
  | {
      readonly ok: false;
      readonly reason: JwtReason;
      /** 401 for a bad token, 503 when we cannot decide (JWKS down, replay cache full). */
      readonly status: 401 | 503;
      /** Present only when the signature was valid, so it is safe to put in an audit event. */
      readonly claims?: BastionClaims;
    };

export interface JwtVerifierOptions {
  readonly keys: KeySource;
  readonly clock: Clock;
  /** This service's name: it must appear in `aud`. Omit for edge, which does not check `aud`. */
  readonly service?: string;
  /** With `service`: every `jti` is single-use. Omit for edge, which never consumes a `jti`. */
  readonly replayCache?: ReplayCache;
}

function failure(reason: JwtReason, claims?: BastionClaims): JwtResult {
  const status = reason === JWT_REASON.JWKS_UNAVAILABLE || reason === JWT_REASON.REPLAY_CACHE_FULL ? 503 : 401;
  return claims ? { ok: false, reason, status, claims } : { ok: false, reason, status };
}

function classifySignatureError(err: unknown): JwtReason {
  if (err instanceof JwksUnavailableError) return JWT_REASON.JWKS_UNAVAILABLE;
  if (err instanceof UnknownKeyError) return JWT_REASON.BAD_SIG;
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' && SIGNATURE_CODES.has(code) ? JWT_REASON.BAD_SIG : JWT_REASON.MALFORMED;
}

function decodePayload(bytes: Uint8Array): BastionClaims | undefined {
  try {
    return parseClaims(JSON.parse(Buffer.from(bytes).toString('utf8')));
  } catch {
    return undefined;
  }
}

/** Extracts the token from an `Authorization: Bearer <jwt>` header, or undefined if it is not that shape. */
export function extractBearerToken(header: string | undefined): string | undefined {
  if (typeof header !== 'string' || header.length > MAX_TOKEN_LENGTH + 7) return undefined;
  return BEARER.exec(header)?.[1];
}

/** Whether verified claims carry `required`. A denial is HTTP 403 with the given reason. */
export function checkScope(
  claims: BastionClaims,
  required: Scope,
): { readonly ok: true } | { readonly ok: false; readonly reason: string; readonly status: 403 } {
  return claims.scope.includes(required)
    ? { ok: true }
    : { ok: false, reason: scopeMissingReason(required), status: 403 };
}

/** Verifies Bastion tokens independently of whoever forwarded them. */
export class JwtVerifier {
  constructor(private readonly opts: JwtVerifierOptions) {
    if (opts.replayCache && !opts.service) {
      throw new RangeError('a replay cache needs a service name');
    }
  }

  /** Checks signature, claims, expiry, audience and (if configured) single use, in that order. */
  async verify(token: string): Promise<JwtResult> {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      return failure(JWT_REASON.MALFORMED);
    }
    let verified;
    try {
      verified = await compactVerify(token, (header) => this.opts.keys.keyFor(header.kid), {
        algorithms: ['EdDSA'],
      });
    } catch (err) {
      return failure(classifySignatureError(err));
    }
    const claims = decodePayload(verified.payload);
    if (!claims) return failure(JWT_REASON.MALFORMED);
    return this.checkClaims(claims, verified.protectedHeader.kid ?? '');
  }

  private checkClaims(claims: BastionClaims, kid: string): JwtResult {
    const nowSec = this.opts.clock.nowSec();
    const lifetime = claims.exp - claims.iat;
    if (claims.iss !== ISSUER || lifetime <= 0 || lifetime > TOKEN_TTL_SECONDS) {
      return failure(JWT_REASON.MALFORMED);
    }
    if (claims.iat > nowSec + MAX_FUTURE_IAT_SECONDS) return failure(JWT_REASON.MALFORMED);
    if (nowSec >= claims.exp) return failure(JWT_REASON.EXPIRED, claims);
    const { service, replayCache } = this.opts;
    if (service !== undefined && !claims.aud.includes(service)) {
      return failure(JWT_REASON.BAD_AUD, claims);
    }
    if (service !== undefined && replayCache) {
      const used = replayCache.consume(service, claims.jti, claims.exp * 1000);
      if (used === 'replayed') return failure(JWT_REASON.REPLAYED, claims);
      if (used === 'full') return failure(JWT_REASON.REPLAY_CACHE_FULL, claims);
    }
    return { ok: true, claims, kid };
  }
}
