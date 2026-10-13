import type { Clock } from '../clock/clock';
import { JWT_REASON, type JwtReason } from './reasons';

/** The claims Bastion puts in every user token. */
export interface TokenClaims {
  /** Subject: the user id. */
  readonly sub: string;
  /** Audience: the services the token is valid for. */
  readonly aud: readonly string[];
  /** Issuer: always "edge" for user tokens. */
  readonly iss: string;
  /** Issued-at (epoch seconds). */
  readonly iat: number;
  /** Expiry (epoch seconds). */
  readonly exp: number;
  /** Single-use nonce, tracked by each service independently. */
  readonly jti: string;
  /** Per-service scopes the token grants. */
  readonly scope: readonly string[];
}

export type ClaimsFailure = {
  readonly ok: false;
  readonly reason: JwtReason;
  readonly detail?: string;
};
export type ClaimsSuccess = { readonly ok: true; readonly claims: TokenClaims };
export type ClaimsCheck = ClaimsSuccess | ClaimsFailure;

function fail(reason: JwtReason, detail?: string): ClaimsFailure {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

/**
 * Structural validation for a decoded JWT payload. Called after signature
 * verification. The Clock is used only for the timestamp checks so tests can
 * simulate expired and not-yet-valid tokens.
 */
export function validateClaims(
  payload: Readonly<Record<string, unknown>>,
  options: {
    readonly expectedAudience: string;
    readonly expectedIssuer: string;
    readonly clock: Clock;
  },
): ClaimsCheck {
  const { expectedAudience, expectedIssuer, clock } = options;

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    return fail(JWT_REASON.MALFORMED, 'sub');
  }
  if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
    return fail(JWT_REASON.MALFORMED, 'jti');
  }
  if (typeof payload.exp !== 'number' || !Number.isInteger(payload.exp)) {
    return fail(JWT_REASON.MALFORMED, 'exp');
  }
  if (typeof payload.iat !== 'number' || !Number.isInteger(payload.iat)) {
    return fail(JWT_REASON.MALFORMED, 'iat');
  }
  if (typeof payload.iss !== 'string') {
    return fail(JWT_REASON.MALFORMED, 'iss');
  }
  if (!isStringArray(payload.aud) || payload.aud.length === 0) {
    return fail(JWT_REASON.MALFORMED, 'aud');
  }
  if (!isStringArray(payload.scope)) {
    return fail(JWT_REASON.MALFORMED, 'scope');
  }

  const nowSec = clock.nowSec();
  if (nowSec >= payload.exp) return fail(JWT_REASON.EXPIRED);
  if (nowSec < payload.iat) return fail(JWT_REASON.NOT_YET_VALID);
  if (payload.iss !== expectedIssuer) return fail(JWT_REASON.BAD_ISSUER);
  if (!payload.aud.includes(expectedAudience)) return fail(JWT_REASON.BAD_AUD);

  return {
    ok: true,
    claims: {
      sub: payload.sub,
      aud: [...payload.aud],
      iss: payload.iss,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
      scope: [...payload.scope],
    },
  };
}

/** Does this token grant `scope`? */
export function hasScope(claims: TokenClaims, scope: string): boolean {
  return claims.scope.includes(scope);
}
