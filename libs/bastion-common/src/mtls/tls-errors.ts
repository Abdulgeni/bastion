import type { Server as HttpsServer } from 'node:https';
import { MTLS_OUTCOME_BY_REASON, MTLS_REASON, type MtlsOutcome, type MtlsReason } from './reasons';

const EXPIRED_CODES: ReadonlySet<string> = new Set(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID']);

const REJECTED_CA_CODES: ReadonlySet<string> = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_UNTRUSTED',
  'CERT_REJECTED',
  'CERT_REVOKED',
  'CERT_SIGNATURE_FAILURE',
  'INVALID_CA',
  'INVALID_PURPOSE',
  'PATH_LENGTH_EXCEEDED',
]);

// OpenSSL/Node emit platform- and version-specific codes when the peer fails to
// present a certificate. The Linux/macOS builds emit the first entry; the Windows
// and TLS 1.3 builds emit one of the others. Treat all of them the same.
const NO_CERT_CODES: ReadonlySet<string> = new Set([
  'ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE',
  'ERR_SSL_SSLV3_ALERT_NO_CERTIFICATE',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_REQUIRED',
  'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
  'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV13_ALERT_HANDSHAKE_FAILURE',
]);

/** A handshake that Node aborted before any HTTP request existed. */
export interface TlsRejection {
  readonly reason: MtlsReason;
  readonly outcome: MtlsOutcome;
  /** Sanitised OpenSSL/Node code explaining the failure, e.g. CERT_HAS_EXPIRED. */
  readonly detail: string;
  readonly remoteAddress?: string;
}

function safeCode(value: unknown): string | undefined {
  const raw = value instanceof Error ? (value as { code?: unknown }).code : value;
  return typeof raw === 'string' && /^[A-Z0-9_]{1,64}$/.test(raw) ? raw : undefined;
}

/**
 * Maps a tlsClientError to an audit reason. Node reports bad-CA and expired
 * certificates as a bare ECONNRESET and puts the real cause in
 * `socket.authorizationError`, so that is checked first.
 *
 * When no client certificate is presented, the reporting varies by platform
 * (see NO_CERT_CODES above), so all known no-cert codes are checked against
 * both the error code and the authorization error.
 */
export function classifyTlsError(
  errorCode: unknown,
  authorizationError: unknown,
): { reason: MtlsReason; detail: string } {
  const auth = safeCode(authorizationError);
  const code = safeCode(errorCode);
  if (auth && EXPIRED_CODES.has(auth)) return { reason: MTLS_REASON.EXPIRED, detail: auth };
  if (auth && REJECTED_CA_CODES.has(auth)) return { reason: MTLS_REASON.REJECTED_CA, detail: auth };
  if (code && NO_CERT_CODES.has(code)) return { reason: MTLS_REASON.NO_CLIENT_CERT, detail: code };
  if (auth && NO_CERT_CODES.has(auth)) return { reason: MTLS_REASON.NO_CLIENT_CERT, detail: auth };
  return { reason: MTLS_REASON.HANDSHAKE_ERROR, detail: auth ?? code ?? 'UNKNOWN' };
}

/**
 * Reports every aborted handshake to `onRejection`. The callback must be
 * quick and must not throw; if it does, the exception is swallowed so a hostile
 * peer can never crash the listener.
 */
export function attachTlsClientErrorHandler(
  server: HttpsServer,
  onRejection: (rejection: TlsRejection) => void,
): void {
  server.on('tlsClientError', (err, socket) => {
    try {
      const { reason, detail } = classifyTlsError(err, socket.authorizationError);
      onRejection({
        reason,
        outcome: MTLS_OUTCOME_BY_REASON[reason],
        detail,
        remoteAddress: socket.remoteAddress,
      });
    } catch {
      // Never let a misbehaving sink take the listener down.
    }
  });
}
