import { X509Certificate, createPrivateKey, type KeyObject } from 'node:crypto';
import type { Clock } from '../clock/clock';
import type { BastionConfig, ServiceName } from '../config/config';
import { ConfigError } from '../errors';
import { readTlsMaterial, type TlsMaterial } from '../mtls/cert-material';
import { extractUriSans } from './san';
import { spiffeIdFor } from './spiffe';
import { certWindowState } from './validity';

/** This process's verified identity: who it is, and the key material that proves it. */
export interface WorkloadIdentity {
  readonly serviceName: ServiceName;
  readonly spiffeId: string;
  readonly material: TlsMaterial;
  /** Epoch ms at which our own certificate expires. */
  readonly notAfterMs: number;
}

interface Parsed {
  readonly cert: X509Certificate;
  readonly ca: X509Certificate;
  readonly key: KeyObject;
}

function parse(material: TlsMaterial): Parsed {
  try {
    return {
      cert: new X509Certificate(material.cert),
      ca: new X509Certificate(material.ca),
      key: createPrivateKey(material.key),
    };
  } catch {
    throw new ConfigError(['TLS material is not valid PEM (cert, key or CA could not be parsed)']);
  }
}

function problems(p: Parsed, expectedId: string, nowMs: number): string[] {
  const issues: string[] = [];
  if (!p.cert.checkPrivateKey(p.key)) issues.push('TLS key does not match TLS cert');
  if (!p.cert.verify(p.ca.publicKey)) issues.push('TLS cert is not signed by the configured CA');
  if (certWindowState(nowMs, p.cert.validFrom, p.cert.validTo) !== 'valid') {
    issues.push('TLS cert is outside its validity window');
  }
  if (certWindowState(nowMs, p.ca.validFrom, p.ca.validTo) !== 'valid') {
    issues.push('TLS CA cert is outside its validity window');
  }
  const uris = extractUriSans(p.cert.subjectAltName);
  if (uris.length !== 1 || uris[0] !== expectedId) {
    issues.push(`TLS cert identity must be exactly ${expectedId}`);
  }
  return issues;
}

/**
 * Loads and validates this service's certificate material. Refuses (ConfigError) if
 * any file is missing, the key does not match, the cert is not signed by the CA, either
 * is outside its validity window, or the cert's SPIFFE ID is not this service's.
 */
export function loadWorkloadIdentity(
  config: Pick<BastionConfig, 'serviceName' | 'trustDomain' | 'tls'>,
  clock: Clock,
): WorkloadIdentity {
  const material = readTlsMaterial(config.tls);
  const parsed = parse(material);
  const spiffeId = spiffeIdFor(config.trustDomain, config.serviceName);
  const issues = problems(parsed, spiffeId, clock.nowMs());
  if (issues.length > 0) throw new ConfigError(issues);
  return {
    serviceName: config.serviceName,
    spiffeId,
    material,
    notAfterMs: Date.parse(parsed.cert.validTo),
  };
}
