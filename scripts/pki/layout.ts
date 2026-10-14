import { X509Certificate } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Clock } from '../../libs/bastion-common/src/clock/clock';
import { certWindowState } from '../../libs/bastion-common/src/identity/validity';
import { loadCaSigner, type CaSigner } from './issue';

const PRIVATE_MODE = 0o600;
const PUBLIC_MODE = 0o644;

/** Where everything lives under the gitignored var/ directory. */
export interface PkiPaths {
  readonly caCert: string;
  readonly caKey: string;
  readonly rogueDir: string;
  serviceCert(service: string): string;
  serviceKey(service: string): string;
  rogueFile(kind: 'self-signed' | 'wrong-id', file: 'cert.pem' | 'key.pem'): string;
}

/** Path layout. Service files match the defaults in bastion-common's config. */
export function pkiPaths(varDir: string): PkiPaths {
  const rogueDir = join(varDir, 'rogue');
  return {
    caCert: join(varDir, 'ca', 'ca.pem'),
    caKey: join(varDir, 'ca', 'ca.key'),
    rogueDir,
    serviceCert: (s) => join(varDir, 'certs', s, 'cert.pem'),
    serviceKey: (s) => join(varDir, 'certs', s, 'key.pem'),
    rogueFile: (kind, file) => join(rogueDir, kind, file),
  };
}

function atomicWrite(path: string, data: string, mode: number): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, { mode });
  chmodSync(tmp, mode);
  renameSync(tmp, path);
}

/** Writes a private key atomically with mode 0600. */
export function writePrivate(path: string, data: string): void {
  atomicWrite(path, data, PRIVATE_MODE);
}

/** Writes a public certificate atomically with mode 0644. */
export function writePublic(path: string, data: string): void {
  atomicWrite(path, data, PUBLIC_MODE);
}

/** True when both CA files exist; throws if only one does (never guess which is right). */
export function caExists(paths: PkiPaths): boolean {
  const cert = existsSync(paths.caCert);
  const key = existsSync(paths.caKey);
  if (cert !== key) {
    throw new Error(`CA files are incomplete (${paths.caCert}, ${paths.caKey}); re-run with --force-ca`);
  }
  return cert;
}

/** Loads the existing CA, refusing if it is missing or outside its validity window. */
export async function readCaSigner(paths: PkiPaths, clock: Clock): Promise<CaSigner> {
  if (!caExists(paths)) {
    throw new Error(`no CA found at ${paths.caCert}; run gen-certs first`);
  }
  const certPem = readFileSync(paths.caCert, 'utf8');
  const keyPem = readFileSync(paths.caKey, 'utf8');
  const nodeCert = new X509Certificate(certPem);
  if (certWindowState(clock.nowMs(), nodeCert.validFrom, nodeCert.validTo) !== 'valid') {
    throw new Error('the CA certificate is outside its validity window; re-run with --force-ca');
  }
  return loadCaSigner(certPem, keyPem);
}
