import { X509Certificate, createPrivateKey, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import type { Clock } from '../../libs/bastion-common/src/clock/clock';
import type { RandomSource } from '../../libs/bastion-common/src/random/random-source';
import { deriveEd25519Keys, importSigningKey } from './keys';

x509.cryptoProvider.set(webcrypto as never);

const ALG = { name: 'Ed25519' };
const DAY_MS = 86_400_000;
/** Certificates start this long before "now" to tolerate clock skew between host and containers. */
const SKEW_MS = 5 * 60_000;

/** Time and randomness sources, injected so tests are reproducible. */
export interface IssueDeps {
  readonly random: RandomSource;
  readonly clock: Clock;
}

/** A PEM certificate and its PKCS#8 PEM private key. */
export interface Credential {
  readonly certPem: string;
  readonly keyPem: string;
}

/** What is needed to sign leaf certificates as the CA. */
export interface CaSigner {
  readonly certPem: string;
  readonly cert: x509.X509Certificate;
  readonly privateKey: webcrypto.CryptoKey;
}

export interface LeafOptions {
  /** Subject CN. Informational only: authorization uses the URI SAN. */
  readonly commonName: string;
  readonly spiffeId: string;
  readonly dnsNames: readonly string[];
  readonly ipAddresses: readonly string[];
  readonly ttlMs: number;
}

function serial(random: RandomSource): string {
  return `01${random.bytes(8).toString('hex')}`;
}

function validity(clock: Clock, ttlMs: number): { notBefore: Date; notAfter: Date } {
  const nowMs = Math.floor(clock.nowMs() / 1000) * 1000;
  return { notBefore: new Date(nowMs - SKEW_MS), notAfter: new Date(nowMs + ttlMs) };
}

function leafExtensions(opts: LeafOptions): x509.Extension[] {
  const names = [
    ...opts.dnsNames.map((value) => ({ type: 'dns' as const, value })),
    ...opts.ipAddresses.map((value) => ({ type: 'ip' as const, value })),
    { type: 'url' as const, value: opts.spiffeId },
  ];
  return [
    new x509.SubjectAlternativeNameExtension(names, false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension(
      [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
      false,
    ),
  ];
}

/** Creates a self-signed Ed25519 root CA (path length 0: it signs leaves only). */
export async function createCa(
  deps: IssueDeps,
  opts: { readonly commonName: string; readonly ttlDays: number },
): Promise<Credential & { readonly signer: CaSigner }> {
  const keys = await deriveEd25519Keys(deps.random);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(deps.random),
    name: `CN=${opts.commonName}`,
    ...validity(deps.clock, opts.ttlDays * DAY_MS),
    signingAlgorithm: ALG,
    keys: { privateKey: keys.privateKey, publicKey: keys.publicKey },
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  const signer: CaSigner = { certPem: cert.toString('pem'), cert, privateKey: keys.privateKey };
  return { certPem: signer.certPem, keyPem: keys.privateKeyPem, signer };
}

/** Rebuilds a CA signer from PEM files, checking the key matches the certificate. */
export async function loadCaSigner(certPem: string, keyPem: string): Promise<CaSigner> {
  const nodeCert = new X509Certificate(certPem);
  if (!nodeCert.ca) throw new Error('certificate is not a CA');
  if (!nodeCert.checkPrivateKey(createPrivateKey(keyPem))) {
    throw new Error('CA private key does not match the CA certificate');
  }
  return {
    certPem,
    cert: new x509.X509Certificate(certPem),
    privateKey: await importSigningKey(keyPem),
  };
}

/** Issues a leaf certificate signed by the CA, with a fresh key pair. */
export async function issueLeaf(
  deps: IssueDeps,
  ca: CaSigner,
  opts: LeafOptions,
): Promise<Credential> {
  const keys = await deriveEd25519Keys(deps.random);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(deps.random),
    subject: `CN=${opts.commonName}`,
    issuer: ca.cert.subject,
    ...validity(deps.clock, opts.ttlMs),
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: ca.privateKey,
    extensions: leafExtensions(opts),
  });
  return { certPem: cert.toString('pem'), keyPem: keys.privateKeyPem };
}

/** Issues a self-signed leaf-shaped certificate that no CA vouches for. */
export async function createSelfSigned(deps: IssueDeps, opts: LeafOptions): Promise<Credential> {
  const keys = await deriveEd25519Keys(deps.random);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(deps.random),
    name: `CN=${opts.commonName}`,
    ...validity(deps.clock, opts.ttlMs),
    signingAlgorithm: ALG,
    keys: { privateKey: keys.privateKey, publicKey: keys.publicKey },
    extensions: leafExtensions(opts),
  });
  return { certPem: cert.toString('pem'), keyPem: keys.privateKeyPem };
}
