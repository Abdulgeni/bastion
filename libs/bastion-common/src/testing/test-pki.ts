import { randomBytes, webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

/**
 * Test-only PKI: an in-memory Ed25519 CA that issues SPIFFE-style leaf certs.
 * Real certificates for running services come from scripts/gen-certs.ts (Step 3).
 */
x509.cryptoProvider.set(webcrypto as never);

const ALG = { name: 'Ed25519' };
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export interface TestCredential {
  readonly cert: string;
  readonly key: string;
}

export interface IssueOptions {
  readonly service: string;
  /** Defaults to spiffe://bastion.local/services/<service>. */
  readonly uri?: string;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
}

async function generateKeys(): Promise<webcrypto.CryptoKeyPair> {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  return keys as webcrypto.CryptoKeyPair;
}

async function privateKeyPem(key: webcrypto.CryptoKey): Promise<string> {
  const der = await webcrypto.subtle.exportKey('pkcs8', key);
  return x509.PemConverter.encode(der, 'PRIVATE KEY');
}

function serial(): string {
  return `01${randomBytes(8).toString('hex')}`;
}

function leafExtensions(service: string, uri: string): x509.Extension[] {
  return [
    new x509.SubjectAlternativeNameExtension(
      [
        { type: 'dns', value: service },
        { type: 'url', value: uri },
      ],
      false,
    ),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension(
      [x509.ExtendedKeyUsage.serverAuth, x509.ExtendedKeyUsage.clientAuth],
      false,
    ),
  ];
}

export class TestPki {
  private constructor(
    readonly caPem: string,
    private readonly caCert: x509.X509Certificate,
    private readonly caKey: webcrypto.CryptoKey,
  ) {}

  static async create(name = 'bastion-test-ca'): Promise<TestPki> {
    const keys = await generateKeys();
    const now = Date.now();
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: serial(),
      name: `CN=${name}`,
      notBefore: new Date(now - HOUR),
      notAfter: new Date(now + 30 * DAY),
      signingAlgorithm: ALG,
      keys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ],
    });
    return new TestPki(cert.toString('pem'), cert, keys.privateKey);
  }

  /** Issues a leaf valid from one hour ago for one day unless overridden. */
  async issue(opts: IssueOptions): Promise<TestCredential> {
    const keys = await generateKeys();
    const now = Date.now();
    const uri = opts.uri ?? `spiffe://bastion.local/services/${opts.service}`;
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial(),
      subject: `CN=${opts.service}`,
      issuer: this.caCert.subject,
      notBefore: opts.notBefore ?? new Date(now - HOUR),
      notAfter: opts.notAfter ?? new Date(now + DAY),
      signingAlgorithm: ALG,
      publicKey: keys.publicKey,
      signingKey: this.caKey,
      extensions: leafExtensions(opts.service, uri),
    });
    return { cert: cert.toString('pem'), key: await privateKeyPem(keys.privateKey) };
  }
}

/** A self-signed certificate claiming `uri`, signed by nobody we trust. */
export async function selfSignedCredential(service: string, uri: string): Promise<TestCredential> {
  const keys = await generateKeys();
  const now = Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: `CN=${service}`,
    notBefore: new Date(now - HOUR),
    notAfter: new Date(now + DAY),
    signingAlgorithm: ALG,
    keys,
    extensions: leafExtensions(service, uri),
  });
  return { cert: cert.toString('pem'), key: await privateKeyPem(keys.privateKey) };
}
