import type { ConnectionOptions, PeerCertificate } from 'node:tls';
import { Agent } from 'undici';
import { extractUriSans } from '../identity/san';
import type { TlsMaterial } from './cert-material';

export interface MtlsClientOptions {
  readonly material: TlsMaterial;
  /** SPIFFE URI the server must present: the workload identity of the callee. */
  readonly expectedServerId: string;
  /** Connect timeout in milliseconds (default 5000). */
  readonly connectTimeoutMs?: number;
}

/**
 * SPIFFE-style server verification: after the chain check, the server's single URI
 * SAN must equal the expected ID. Hostname/DNS is deliberately not consulted.
 */
export function spiffeServerCheck(
  expectedId: string,
): (hostname: string, cert: PeerCertificate) => Error | undefined {
  return (_hostname, cert) => {
    const uris = extractUriSans(cert.subjectaltname);
    if (uris.length === 1 && uris[0] === expectedId) return undefined;
    return new Error('server identity does not match the expected SPIFFE ID');
  };
}

/** TLS connect options for an outbound mTLS call (usable with undici or node:https). */
export function buildMtlsConnectOptions(
  opts: MtlsClientOptions,
): ConnectionOptions & { timeout: number } {
  return {
    cert: opts.material.cert,
    key: opts.material.key,
    ca: opts.material.ca,
    minVersion: 'TLSv1.3',
    rejectUnauthorized: true,
    checkServerIdentity: spiffeServerCheck(opts.expectedServerId),
    timeout: opts.connectTimeoutMs ?? 5000,
  };
}

/** undici Agent that presents our client cert and verifies the callee's SPIFFE ID. */
export function createMtlsAgent(opts: MtlsClientOptions): Agent {
  return new Agent({ connect: buildMtlsConnectOptions(opts) });
}
