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
    if ('reason' in header) return header;

    const keys = await this.loadKeys();
    if ('reason' in keys) return keys;

    const verified = await this.verifySignature(token, keys.keys);
    if ('reason' in verified) return verified;

    const claims = validateClaims(verified.payload, {
      expectedAudience: this.options.expectedAudience,
      expectedIssuer: this.options.expectedIssuer,
      clock: this.options.clock,
    });
    if (!claims.ok) return claims;

    return this.claimReplay(claims.claims);
  }

  private readHeader(token: string): { kid: string } | VerifyResult {
    try {
      const kid = decodeProtectedHeader(token).kid;
      if (typeof kid !== 'string' || kid.length === 0) {
        return { ok: false, reason: JWT_REASON.MALFORMED, detail: 'kid' };
      }
      return { kid };
    } catch {
      return { ok: false, reason: JWT_REASON.MALFORMED, detail: 'header' };
    }
  }

  private async loadKeys(): Promise<{ keys: unknown[] } | VerifyResult> {
    try {
      return (await this.options.jwks.localResolver()) as { keys: unknown[] };
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
  ): Promise<{ payload: Record<string, unknown> } | VerifyResult> {
    try {
      const result = await jwtVerify(token, createLocalJWKSet(keys as never), {
        currentDate: this.options.clock.now(),
        clockTolerance: 0,
        issuer: this.options.expectedIssuer,
        audience: this.options.expectedAudience,
      } as never);
      return { payload: result.payload as Record<string, unknown> };
    } catch (err) {
      const name = (err as { code?: string }).code ?? (err as Error).name;
      if (name === 'ERR_JWT_EXPIRED') return { ok: false, reason: JWT_REASON.EXPIRED };
      if (name === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
        return { ok: false, reason: JWT_REASON.BAD_AUD };
      }
      if (name === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
        return { ok: false, reason: JWT_REASON.BAD_SIG };
      }
      return { ok: false, reason: JWT_REASON.BAD_SIG, detail: String(name) };
    }
  }

  private claimReplay(claims: TokenClaims): VerifyResult {
    const claimed = this.options.replay.claim(claims.jti, claims.exp);
    if (claimed === 'replayed') return { ok: false, reason: JWT_REASON.REPLAYED };
    if (claimed === 'too-full') {
      return { ok: false, reason: JWT_REASON.JWKS_UNAVAILABLE, detail: 'replay-cache-full' };
    }
    return { ok: true, claims };
  }
}
