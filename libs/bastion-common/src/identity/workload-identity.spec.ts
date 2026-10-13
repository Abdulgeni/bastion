import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeClock } from '../clock/clock';
import { ConfigError } from '../errors';
import { TestPki, type TestCredential } from '../testing/test-pki';
import { loadWorkloadIdentity } from './workload-identity';

const HOUR = 3_600_000;
let dir: string;
let pki: TestPki;
let counter = 0;

beforeAll(async () => {
  pki = await TestPki.create();
});

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'bastion-wi-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function config(cred: TestCredential, caPem = pki.caPem) {
  const sub = join(dir, `set-${counter++}`);
  const files = { certFile: `${sub}.cert`, keyFile: `${sub}.key`, caFile: `${sub}.ca` };
  writeFileSync(files.certFile, cred.cert);
  writeFileSync(files.keyFile, cred.key);
  writeFileSync(files.caFile, caPem);
  return { serviceName: 'orders' as const, trustDomain: 'bastion.local', tls: files };
}

const now = () => new FakeClock(Date.now());

describe('loadWorkloadIdentity', () => {
  it('loads a correct identity', async () => {
    const id = loadWorkloadIdentity(config(await pki.issue({ service: 'orders' })), now());
    expect(id.spiffeId).toBe('spiffe://bastion.local/services/orders');
    expect(id.serviceName).toBe('orders');
    expect(id.notAfterMs).toBeGreaterThan(Date.now());
    expect(id.material.cert.length).toBeGreaterThan(0);
  });

  it("refuses another service's certificate", async () => {
    const cfg = config(await pki.issue({ service: 'payments' }));
    expect(() => loadWorkloadIdentity(cfg, now())).toThrow(/identity must be exactly/);
  });

  it('refuses a certificate from a foreign trust domain', async () => {
    const cred = await pki.issue({ service: 'orders', uri: 'spiffe://rogue.local/services/orders' });
    expect(() => loadWorkloadIdentity(config(cred), now())).toThrow(/identity must be exactly/);
  });

  it('refuses a key that does not match the certificate', async () => {
    const a = await pki.issue({ service: 'orders' });
    const b = await pki.issue({ service: 'orders' });
    expect(() => loadWorkloadIdentity(config({ cert: a.cert, key: b.key }), now())).toThrow(
      /does not match/,
    );
  });

  it('refuses a certificate not signed by the configured CA', async () => {
    const other = await TestPki.create('other-ca');
    const cfg = config(await other.issue({ service: 'orders' }));
    expect(() => loadWorkloadIdentity(cfg, now())).toThrow(/not signed by the configured CA/);
  });

  it('refuses an expired or not-yet-valid certificate, per the Clock', async () => {
    const cfg = config(await pki.issue({ service: 'orders' }));
    expect(() => loadWorkloadIdentity(cfg, new FakeClock(Date.now() + 48 * HOUR))).toThrow(
      /validity window/,
    );
    expect(() => loadWorkloadIdentity(cfg, new FakeClock(Date.now() - 3 * HOUR))).toThrow(
      /validity window/,
    );
  });

  it('refuses when files are missing', () => {
    const files = {
      certFile: join(dir, 'nope.cert'),
      keyFile: join(dir, 'nope.key'),
      caFile: join(dir, 'nope.ca'),
    };
    const cfg = { serviceName: 'orders' as const, trustDomain: 'bastion.local', tls: files };
    expect(() => loadWorkloadIdentity(cfg, now())).toThrow(/cannot read/);
    expect(() => loadWorkloadIdentity(cfg, now())).toThrow(ConfigError);
  });

  it('refuses garbage PEM without leaking its content', async () => {
    const cfg = config({ cert: 'not a cert SECRET-MARKER', key: 'not a key' });
    let message = '';
    try {
      loadWorkloadIdentity(cfg, now());
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/not valid PEM/);
    expect(message).not.toContain('SECRET-MARKER');
  });
});
