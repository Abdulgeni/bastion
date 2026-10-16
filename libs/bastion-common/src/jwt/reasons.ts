/** Audit `reason` strings for token and scope decisions. */
export const JWT_REASON = {
  OK: 'jwt+ok',
  EXPIRED: 'jwt+expired',
  BAD_AUD: 'jwt+bad_aud',
  REPLAYED: 'jwt+replayed',
  BAD_SIG: 'jwt+bad_sig',
  MALFORMED: 'jwt+malformed',
  JWKS_UNAVAILABLE: 'jwks+unavailable',
  REPLAY_CACHE_FULL: 'replay+cache_full',
} as const;

export type JwtReason = (typeof JWT_REASON)[keyof typeof JWT_REASON];

/** Values of the `outcome` label on `bastion_jwt_validation_total`. */
export type JwtOutcome = 'ok' | 'expired' | 'bad_aud' | 'replayed' | 'bad_sig' | 'malformed';

/** Reasons that are not token verdicts (503s) have no metric outcome. */
export const JWT_OUTCOME_BY_REASON: Readonly<Partial<Record<JwtReason, JwtOutcome>>> = {
  [JWT_REASON.OK]: 'ok',
  [JWT_REASON.EXPIRED]: 'expired',
  [JWT_REASON.BAD_AUD]: 'bad_aud',
  [JWT_REASON.REPLAYED]: 'replayed',
  [JWT_REASON.BAD_SIG]: 'bad_sig',
  [JWT_REASON.MALFORMED]: 'malformed',
};

/** The audit reason for a missing scope, e.g. `scope+missing:payments:charge`. */
export function scopeMissingReason(scope: string): string {
  return `scope+missing:${scope}`;
}
