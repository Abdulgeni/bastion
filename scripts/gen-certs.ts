import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ConfigError } from '../libs/bastion-common/src/errors';
import { SERVICE_NAMES, type ServiceName } from '../libs/bastion-common/src/config/config';
import { parseSpiffeId, spiffeIdFor } from '../libs/bastion-common/src/identity/spiffe';
import { createCa, issueLeaf, type CaSigner, type LeafOptions } from './pki/issue';
import { readCliOptions, runCli, type PkiOptions } from './pki/cli-options';
import { caExists, pkiPaths, readCaSigner, writePrivate, writePublic, type PkiPaths } from './pki/layout';

export interface GenCertsResult {
  readonly caCreated: boolean;
  readonly issued: readonly ServiceName[];
  readonly kept: readonly ServiceName[];
}

/** Certificate shape for one service. Edge also answers to localhost for host-side clients. */
export function leafOptionsFor(service: ServiceName, opts: PkiOptions): LeafOptions {
  const spiffeId = spiffeIdFor(opts.trustDomain, service);
  if (!parseSpiffeId(spiffeId)) {
    throw new ConfigError(['BASTION_TRUST_DOMAIN must be a lowercase DNS-style name']);
  }
  const isEdge = service === 'edge';
  return {
    commonName: service,
    spiffeId,
    dnsNames: isEdge ? ['edge', 'localhost'] : [service],
    ipAddresses: isEdge ? ['127.0.0.1'] : [],
    ttlMs: opts.certTtlHours * 3_600_000,
  };
}

/** Issues a fresh key and certificate for one service and writes both (key 0600, cert 0644). */
export async function issueService(
  paths: PkiPaths,
  ca: CaSigner,
  opts: PkiOptions,
  service: ServiceName,
): Promise<void> {
  const cred = await issueLeaf(opts, ca, leafOptionsFor(service, opts));
  writePrivate(paths.serviceKey(service), cred.keyPem);
  writePublic(paths.serviceCert(service), cred.certPem);
}

/** True if the service's files are missing, unreadable, mismatched, foreign, or expiring soon. */
function needsIssue(paths: PkiPaths, service: ServiceName, ca: CaSigner, opts: PkiOptions): boolean {
  try {
    const cert = new X509Certificate(readFileSync(paths.serviceCert(service)));
    const key = createPrivateKey(readFileSync(paths.serviceKey(service)));
    const caCert = new X509Certificate(ca.certPem);
    const now = opts.clock.nowMs();
    const started = Date.parse(cert.validFrom) <= now;
    const remaining = Date.parse(cert.validTo) - now;
    const healthy = cert.checkPrivateKey(key) && cert.verify(caCert.publicKey);
    return !(healthy && started && remaining > opts.renewWindowMs);
  } catch {
    return true;
  }
}

async function createAndWriteCa(paths: PkiPaths, opts: PkiOptions): Promise<CaSigner> {
  const ca = await createCa(opts, { commonName: 'bastion-dev-ca', ttlDays: opts.caTtlDays });
  writePrivate(paths.caKey, ca.keyPem);
  writePublic(paths.caCert, ca.certPem);
  return ca.signer;
}

/**
 * Ensures the dev CA and every service certificate exist. Idempotent: an existing CA is
 * reused, and only missing, broken or soon-to-expire service certs are re-issued.
 * `forceCa` replaces the CA, which re-issues everything.
 */
export async function generateAll(
  opts: PkiOptions,
  flags: { readonly forceCa?: boolean } = {},
): Promise<GenCertsResult> {
  const paths = pkiPaths(opts.varDir);
  const reuse = flags.forceCa !== true && caExists(paths);
  const ca = reuse ? await readCaSigner(paths, opts.clock) : await createAndWriteCa(paths, opts);
  const issued: ServiceName[] = [];
  const kept: ServiceName[] = [];
  for (const service of SERVICE_NAMES) {
    if (!reuse || needsIssue(paths, service, ca, opts)) {
      await issueService(paths, ca, opts, service);
      issued.push(service);
    } else {
      kept.push(service);
    }
  }
  return { caCreated: !reuse, issued, kept };
}

async function main(): Promise<void> {
  const opts = readCliOptions(process.env, process.argv.slice(2));
  const result = await generateAll(opts, { forceCa: opts.forceCa });
  process.stdout.write(`CA: ${result.caCreated ? 'created' : 'reused'} (${opts.varDir}/ca/ca.pem)\n`);
  process.stdout.write(`issued: ${result.issued.join(', ') || '(none)'}\n`);
  process.stdout.write(`kept:   ${result.kept.join(', ') || '(none)'}\n`);
}

if (require.main === module) runCli(main);
