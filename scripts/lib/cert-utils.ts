/**
 * X.509 certificate construction using @peculiar/x509 and Node's webcrypto.
 *
 * Certs use Ed25519 (deterministic signatures, RFC 8410 key encoding). Every
 * leaf carries both a DNS SAN (for human tooling like curl) and a SPIFFE URI
 * SAN (for peer identity checks, per design decision F7).
 */
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { privateKeyToPem } from './seed';

x509.cryptoProvider.set(webcrypto as never);

const ALG = { name: 'Ed25519' } as const;

export interface IssuedLeaf {
  readonly certPem: string;
  readonly keyPem: string;
  readonly cert: x509.X509Certificate;
  readonly key: webcrypto.CryptoKey;
}

export interface LoadedCa {
  readonly certPem: string;
  readonly keyPem: string;
  readonly cert: x509.X509Certificate;
  readonly key: webcrypto.CryptoKey;
}

export interface CaOptions {
  readonly name: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly serialHex: string;
}

/** Build a self-signed CA cert from a pre-built Ed25519 key pair. */
export async function createCa(
  keyPair: webcrypto.CryptoKeyPair,
  options: CaOptions,
): Promise<LoadedCa> {
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: options.serialHex,
    name: `CN=${options.name}`,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signingAlgorithm: ALG,
    keys: keyPair,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  const certPem = cert.toString('pem');
  const keyPem = await privateKeyToPem(keyPair.privateKey);
  return { certPem, keyPem, cert, key: keyPair.privateKey };
}

export interface LeafOptions {
  readonly service: string;
  readonly uri: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly serialHex: string;
}

/** Issue a leaf cert signed by `ca`. `keyPair` provides the leaf's own key. */
export async function issueLeaf(
  ca: { cert: x509.X509Certificate; key: webcrypto.CryptoKey },
  keyPair: webcrypto.CryptoKeyPair,
  options: LeafOptions,
): Promise<IssuedLeaf> {
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: options.serialHex,
    subject: `CN=${options.service}`,
    issuer: ca.cert.subject,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signingAlgorithm: ALG,
    publicKey: keyPair.publicKey,
    signingKey: ca.key,
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: 'dns', value: options.service },
          { type: 'url', value: options.uri },
        ],
        false,
      ),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
    ],
  });
  const certPem = cert.toString('pem');
  const keyPem = await privateKeyToPem(keyPair.privateKey);
  return { certPem, keyPem, cert, key: keyPair.privateKey };
}

/** Build a self-signed leaf: signed by itself, not by any CA. */
export async function selfSignedLeaf(
  keyPair: webcrypto.CryptoKeyPair,
  options: LeafOptions,
): Promise<IssuedLeaf> {
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: options.serialHex,
    name: `CN=${options.service}`,
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signingAlgorithm: ALG,
    keys: keyPair,
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        [
          { type: 'dns', value: options.service },
          { type: 'url', value: options.uri },
        ],
        false,
      ),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
    ],
  });
  const certPem = cert.toString('pem');
  const keyPem = await privateKeyToPem(keyPair.privateKey);
  return { certPem, keyPem, cert, key: keyPair.privateKey };
}

/** Parse a PEM cert back into an X509Certificate. */
export function parseCert(pem: string): x509.X509Certificate {
  return new x509.X509Certificate(pem);
}

export interface MaterialPaths {
  readonly caDir: string;
  readonly certsDir: string;
}

export function defaultMaterialPaths(varDir: string): MaterialPaths {
  return {
    caDir: `${varDir}/ca`,
    certsDir: `${varDir}/certs`,
  };
}
