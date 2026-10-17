import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import type { Clock } from '../clock/clock';
import { validateClaims, type TokenClaims } from './claims';
import { JwksCache, JwksUnavailableError } from './jwks-cache';
import { JWT_REASON, type JwtReason } from './reasons';
import { ReplayCache } from './replay-cache';

export interface VerifyOptions {
  readonly serviceName: string;
  readonly expectedAudience: string;
  readonly expectedIssuer: string;
  readonly clock: Clock;
  readonly jwks: JwksCache;
  readonly replay: ReplayCache;
  /** Edge: skip the aud check because tokens are addressed to downstream services. */
  readonly skipAudienceCheck?: boolean;
}

export type VerifyResult =
  | { readonly ok: true; readonly claims: TokenClaims }
  | { readonly ok: false; readonly reason: JwtReason; readonly detail?: string };

type HeaderOk = { readonly kind: 'header'; readonly kid: string };
type KeysOk = { readonly kind: 'keys'; readonly keys: unknown[] };
type PayloadOk = { readonly kind: 'payload'; readonly payload: Record<string, unknown> };

/** Maps a jose error code to a Bastion reason. Unknown codes are BAD_SIG. */
function reasonForJoseError(code: string | undefined, name: string | undefined): {
  reason: JwtReason;
  detail?: string;
} {
  switch (code ?? name) {
    case 'ERR_JWT_EXPIRED':
      return { reason: JWT_REASON.EXPIRED };
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      return { reason: JWT_REASON.BAD_AUD };
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED_ISS':
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED_ISSUER':
      return { reason: JWT_REASON.BAD_ISSUER };
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
      return { reason: JWT_REASON.BAD_SIG };
    case 'ERR_JWS_INVALID':
    case 'ERR_JWT_INVALID':
      return { reason: JWT_REASON.MALFORMED };
    default:
      return { reason: JWT_REASON.BAD_SIG, detail: String(code ?? name) };
  }
}

/**
 * Verifies a user token end to end:
 *  1. Parse the header and reject a token with no `kid`.
 *  2. Fetch a fresh-enough JWKS; unreachable JWKS fails closed with a distinct
 *     `jwks+unavailable` reason so the caller can return 503.
 *  3. Verify the signature against the JWKS by `kid`.
 *  4. Structural + temporal + audience validation via `validateClaims`.
 *  5. Single-use `jti` claim on the per-service replay cache.
 *
 * `currentDate` in jwtVerify is pulled from the injected Clock, so tests can
 * control time without touching the system clock.
 */
export class TokenVerifier {
  constructor(private readonly options: VerifyOptions) {}

  async verify(token: string | undefined): Promise<VerifyResult> {
    if (!token || token.trim().length === 0) {
      return { ok: false, reason: JWT_REASON.MISSING };
    }

    const header = this.readHeader(token);
    if ('ok' in header) return header;

    const keys = await this.loadKeys();
    if ('ok' in keys) return keys;

    const verified = await this.verifySignature(token, keys.keys);
    if ('ok' in verified) return verified;

    const claims = validateClaims(verified.payload, {
      expectedAudience: this.options.expectedAudience,
      expectedIssuer: this.options.expectedIssuer,
      clock: this.options.clock,
      skipAudienceCheck: this.options.skipAudienceCheck,
    });
    if (!claims.ok) return claims;

    return this.claimReplay(claims.claims);
  }

  private readHeader(token: string): HeaderOk | VerifyResult {
    try {
      const kid = decodeProtectedHeader(token).kid;
      if (typeof kid !== 'string' || kid.length === 0) {
        return { ok: false, reason: JWT_REASON.MALFORMED, detail: 'kid' };
      }
      return { kind: 'header', kid };
    } catch {
      return { ok: false, reason: JWT_REASON.MALFORMED, detail: 'header' };
    }
  }

  private async loadKeys(): Promise<KeysOk | VerifyResult> {
    try {
      const resolved = await this.options.jwks.localResolver();
      return { kind: 'keys', keys: resolved.keys };
    } catch (err) {
      if (err instanceof JwksUnavailableError) {
        return { ok: false, reason: JWT_REASON.JWKS_UNAVAILABLE };
      }
      return { ok: false, reason: JWT_REASON.JWKS_UNAVAILABLE };
    }
  }

  private async verifySignature(
    token: string,
    keys: unknown[],
  ): Promise<PayloadOk | VerifyResult> {
    try {
      const result = await jwtVerify(token, createLocalJWKSet({ keys } as never), {
        currentDate: this.options.clock.now(),
        clockTolerance: 0,
        issuer: this.options.expectedIssuer,
        // Edge: no audience — tokens are addressed to downstream services,
        // and jose would reject them here before validateClaims can run.
        ...(this.options.skipAudienceCheck === true ? {} : { audience: this.options.expectedAudience }),
      } as never);
      return { kind: 'payload', payload: result.payload as Record<string, unknown> };
    } catch (err) {
      const code = (err as { code?: string }).code;
      const name = (err as Error).name;
      return { ok: false, ...reasonForJoseError(code, name) };
    }
  }

  private claimReplay(claims: TokenClaims): VerifyResult {
    const claimed = this.options.replay.claim(claims.jti, claims.exp);
    if (claimed === 'replayed') return { ok: false, reason: JWT_REASON.REPLAYED };
    if (claimed === 'too-full') {
      // Distinct reason so operators can tell capacity pressure from a JWKS outage.
      return { ok: false, reason: JWT_REASON.REPLAY_CACHE_FULL };
    }
    return { ok: true, claims };
  }
}

/**
 * Aliases and helpers added for Step 5's guard. They do not change the
 * behaviour of TokenVerifier or VerifyResult; they exist so callers can
 * import under either name and so the guard can share the bearer-token
 * parsing and scope-checking logic.
 */

/** Alias for VerifyResult so Step 5's guard can import either name. */
export type JwtResult = VerifyResult;

/** Alias for TokenVerifier so Step 5's guard can import either name. */
export { TokenVerifier as JwtVerifier };

/** Maximum length of a bearer token, matching MAX_TOKEN_LENGTH above. */
const MAX_BEARER_TOKEN_LENGTH = 4096;

/** `Bearer <jwt>` where each segment is base64url. */
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/**
 * Extracts the token from an `Authorization: Bearer <jwt>` header, or
 * undefined if it is not that shape.
 */
export function extractBearerToken(header: string | undefined): string | undefined {
  if (typeof header !== 'string' || header.length > MAX_BEARER_TOKEN_LENGTH + 7) return undefined;
  return BEARER.exec(header)?.[1];
}

/**
 * Whether verified claims carry `required`. A denial is HTTP 403 with the
 * given reason.
 */
export function checkScope(
  claims: TokenClaims,
  required: string,
): { readonly ok: true } | { readonly ok: false; readonly reason: string; readonly status: 403 } {
  return claims.scope.includes(required)
    ? { ok: true }
    : { ok: false, reason: `scope+missing:${required}`, status: 403 };
}
