/** Audit `reason` strings for transport-level (mTLS) decisions. */
export const MTLS_REASON = {
  OK: 'mtls+ok',
  NO_CLIENT_CERT: 'mtls+no-client-cert',
  REJECTED_CA: 'mtls+rejected_ca',
  EXPIRED: 'mtls+expired',
  BAD_IDENTITY: 'mtls+bad-identity',
  HANDSHAKE_ERROR: 'mtls+handshake-error',
} as const;

export type MtlsReason = (typeof MTLS_REASON)[keyof typeof MTLS_REASON];

/** Values of the `outcome` label on `bastion_mtls_handshake_total`. */
export type MtlsOutcome =
  | 'accepted'
  | 'rejected_ca'
  | 'rejected_identity'
  | 'rejected_expired'
  | 'no_client_cert'
  | 'handshake_error';

export const MTLS_OUTCOME_BY_REASON: Readonly<Record<MtlsReason, MtlsOutcome>> = {
  [MTLS_REASON.OK]: 'accepted',
  [MTLS_REASON.NO_CLIENT_CERT]: 'no_client_cert',
  [MTLS_REASON.REJECTED_CA]: 'rejected_ca',
  [MTLS_REASON.EXPIRED]: 'rejected_expired',
  [MTLS_REASON.BAD_IDENTITY]: 'rejected_identity',
  [MTLS_REASON.HANDSHAKE_ERROR]: 'handshake_error',
};
