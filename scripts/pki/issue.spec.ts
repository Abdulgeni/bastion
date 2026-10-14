import { X509Certificate, createPrivateKey } from 'node:crypto';
import { FakeClock } from '../../libs/bastion-common/src/clock/clock';
import { extractUriSans } from '../../libs/bastion-common/src/identity/san';
import { SeededRandom } from '../../libs/bastion-common/src/random/random-source';
import {
  createCa,
  createSelfSigned,
  issueLeaf,
  loadCaSigner,
  type IssueDeps,
  type LeafOptions,
} from './issue';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const EDGE_ID = 'spiffe://bastion.local/services/edge';
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

const deps = (seed = 'seed'): IssueDeps => ({
  random: new SeededRandom(seed),
  clock: new FakeClock(NOW),
});

const edge: LeafOptions = {
  commonName: 'edge',
  spiffeId: EDGE_ID,
  dnsNames: ['edge', 'localhost'],
  ipAddresses: ['127.0.0.1'],
  ttlMs: 24 * 3_600_000,
};

describe('createCa', () => {
  it('creates a self-signed CA valid from 5 minutes ago for the requested days', async () => {
    const ca = await createCa(deps(), { commonName: 'test-ca', ttlDays: 30 });
    const cert = new X509Certificate(ca.certPem);
    expect(cert.ca).toBe(true);
    expect(cert.subject).toBe('CN=test-ca');
    expect(cert.verify(cert.publicKey)).toBe(true);
    expect(Date.parse(cert.validFrom)).toBe(NOW - 5 * 60_000);
    expect(Date.parse(cert.validTo)).toBe(NOW + 30 * 86_400_000);
    expect(cert.checkPrivateKey(createPrivateKey(ca.keyPem))).toBe(true);
  });
});

describe('issueLeaf', () => {
  it('issues a CA-signed cert carrying the SPIFFE ID, DNS and IP names, and both EKUs', async () => {
    const d = deps();
    const ca = await createCa(d, { commonName: 'test-ca', ttlDays: 30 });
    const leaf = await issueLeaf(d, ca.signer, edge);
    const cert = new X509Certificate(leaf.certPem);
    const caCert = new X509Certificate(ca.certPem);
    expect(cert.ca).toBe(false);
    expect(cert.subject).toBe('CN=edge');
    expect(cert.verify(caCert.publicKey)).toBe(true);
    expect(cert.checkIssued(caCert)).toBe(true);
    expect(cert.checkPrivateKey(createPrivateKey(leaf.keyPem))).toBe(true);
    expect(extractUriSans(cert.subjectAltName)).toEqual([EDGE_ID]);
    expect(cert.subjectAltName).toContain('DNS:localhost');
    expect(cert.subjectAltName).toContain('IP Address:127.0.0.1');
    expect(cert.keyUsage).toContain(SERVER_AUTH);
    expect(cert.keyUsage).toContain(CLIENT_AUTH);
    expect(Date.parse(cert.validTo)).toBe(NOW + edge.ttlMs);
  });
});

describe('createSelfSigned', () => {
  it('is not vouched for by the CA', async () => {
    const d = deps();
    const ca = await createCa(d, { commonName: 'test-ca', ttlDays: 30 });
    const forged = new X509Certificate((await createSelfSigned(d, edge)).certPem);
    expect(forged.verify(new X509Certificate(ca.certPem).publicKey)).toBe(false);
    expect(forged.verify(forged.publicKey)).toBe(true);
    expect(extractUriSans(forged.subjectAltName)).toEqual([EDGE_ID]);
  });
});

describe('determinism', () => {
  async function chain(seed: string) {
    const d = deps(seed);
    const ca = await createCa(d, { commonName: 'test-ca', ttlDays: 30 });
    const leaf = await issueLeaf(d, ca.signer, edge);
    return [ca.certPem, ca.keyPem, leaf.certPem, leaf.keyPem].join('\n');
  }

  it('is byte-identical for the same seed and clock', async () => {
    expect(await chain('seed')).toBe(await chain('seed'));
  });

  it('differs for a different seed', async () => {
    expect(await chain('seed')).not.toBe(await chain('other'));
  });
});

describe('loadCaSigner', () => {
  it('rebuilds a signer that can issue valid leaves', async () => {
    const d = deps();
    const ca = await createCa(d, { commonName: 'test-ca', ttlDays: 30 });
    const signer = await loadCaSigner(ca.certPem, ca.keyPem);
    const leaf = await issueLeaf(d, signer, edge);
    expect(
      new X509Certificate(leaf.certPem).verify(new X509Certificate(ca.certPem).publicKey),
    ).toBe(true);
  });

  it('rejects a key that does not match the certificate', async () => {
    const d = deps();
    const a = await createCa(d, { commonName: 'ca-a', ttlDays: 30 });
    const b = await createCa(d, { commonName: 'ca-b', ttlDays: 30 });
    await expect(loadCaSigner(a.certPem, b.keyPem)).rejects.toThrow(/does not match/);
  });

  it('rejects a certificate that is not a CA', async () => {
    const d = deps();
    const ca = await createCa(d, { commonName: 'test-ca', ttlDays: 30 });
    const leaf = await issueLeaf(d, ca.signer, edge);
    await expect(loadCaSigner(leaf.certPem, leaf.keyPem)).rejects.toThrow(/not a CA/);
  });
});
