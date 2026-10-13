import type { ServerOptions } from 'node:https';
import type { TlsMaterial } from './cert-material';

/**
 * Options for an mTLS data-plane listener: the client MUST present a certificate
 * chaining to our CA, otherwise Node aborts the handshake (see tls-errors.ts).
 * TLS 1.3 only.
 */
export function mtlsServerOptions(material: TlsMaterial): ServerOptions {
  return {
    cert: material.cert,
    key: material.key,
    ca: material.ca,
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.3',
  };
}

/**
 * Options for edge's client-facing listener: server-auth TLS only (design
 * decision 1). No client certificate is requested; users authenticate with a JWT.
 */
export function serverAuthOptions(material: Pick<TlsMaterial, 'cert' | 'key'>): ServerOptions {
  return {
    cert: material.cert,
    key: material.key,
    requestCert: false,
    minVersion: 'TLSv1.2',
  };
}
