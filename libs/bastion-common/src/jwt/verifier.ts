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
        audience: this.options.expectedAudience,
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
