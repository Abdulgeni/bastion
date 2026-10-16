/** Audit `reason` strings for JWT and JWKS decisions. */
export const JWT_REASON = {
  OK: 'jwt+ok',
  MISSING: 'jwt+missing',
  MALFORMED: 'jwt+malformed',
  BAD_SIG: 'jwt+bad_sig',
  EXPIRED: 'jwt+expired',
  NOT_YET_VALID: 'jwt+not-yet-valid',
  BAD_AUD: 'jwt+bad_aud',
  BAD_ISSUER: 'jwt+bad-issuer',
  REPLAYED: 'jwt+replayed',
  MISSING_SCOPE: 'scope+missing',
  JWKS_UNAVAILABLE: 'jwks+unavailable',
  REPLAY_CACHE_FULL: 'replay+cache_full',
} as const;

export type JwtReason = (typeof JWT_REASON)[keyof typeof JWT_REASON];

/** Values of the `outcome` label on `bastion_jwt_validation_total`. */
export type JwtOutcome =
  | 'ok'
  | 'missing'
  | 'malformed'
  | 'bad_sig'
  | 'expired'
  | 'not_yet_valid'
  | 'bad_aud'
  | 'bad_issuer'
  | 'replayed'
  | 'jwks_unavailable'
  | 'replay_cache_full';

/**
 * Reason → outcome mapping. `JWKS_UNAVAILABLE` and `REPLAY_CACHE_FULL` are
 * both 503s: they say "we could not decide", not "the token is bad", but
 * they carry distinct metric labels so an operator can tell them apart.
 */
export const JWT_OUTCOME_BY_REASON: Readonly<Record<JwtReason, JwtOutcome>> = {
  [JWT_REASON.OK]: 'ok',
  [JWT_REASON.MISSING]: 'missing',
  [JWT_REASON.MALFORMED]: 'malformed',
  [JWT_REASON.BAD_SIG]: 'bad_sig',
  [JWT_REASON.EXPIRED]: 'expired',
  [JWT_REASON.NOT_YET_VALID]: 'not_yet_valid',
  [JWT_REASON.BAD_AUD]: 'bad_aud',
  [JWT_REASON.BAD_ISSUER]: 'bad_issuer',
  [JWT_REASON.REPLAYED]: 'replayed',
  [JWT_REASON.MISSING_SCOPE]: 'malformed',
  [JWT_REASON.JWKS_UNAVAILABLE]: 'jwks_unavailable',
  [JWT_REASON.REPLAY_CACHE_FULL]: 'replay_cache_full',
};

/** Scopes Bastion defines. Each endpoint declares one. */
export const SCOPES = {
  ORDERS_WRITE: 'orders:write',
  INVENTORY_RESERVE: 'inventory:reserve',
  PAYMENTS_CHARGE: 'payments:charge',
} as const;

export type Scope = (typeof SCOPES)[keyof typeof SCOPES];

/**
 * The audit reason for a missing scope, e.g. `scope+missing:payments:charge`.
 * Distinct from `JWT_REASON.MISSING_SCOPE` (bare) so an audit event can name
 * exactly which scope was absent.
 */
export function scopeMissingReason(scope: string): string {
  return `${JWT_REASON.MISSING_SCOPE}:${scope}`;
}
