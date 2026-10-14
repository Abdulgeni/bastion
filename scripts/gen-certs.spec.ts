import { X509Certificate } from 'node:crypto';
import { readFileSync, rmSync, statSync } from 'node:fs';
import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import { ConfigError } from '../libs/bastion-common/src/errors';
import { SERVICE_NAMES } from '../libs/bastion-common/src/config/config';
import { loadWorkloadIdentity } from '../libs/bastion-common/src/identity/workload-identity';
import { SeededRandom } from '../libs/bastion-common/src/random/random-source';
import { generateAll } from './gen-certs';
import { pkiPaths } from './pki/layout';
import {
  configFor,
  mtlsCall,
  readTree,
  startOrdersServer,
  testOptions,
  tmpVar,
} from './pki/test-helpers';

const DAY = 86_400_000;
const mode = (path: string) => statSync(path).mode & 0o777;
const read = (path: string) => readFileSync(path, 'utf8');
// POSIX mode bits cannot be set on Windows/NTFS; the assertions are POSIX-only.
const posixOnly = process.platform === 'win32' ? it.skip : it;

describe('generateAll', () => {
  it('creates a CA and a certificate every service accepts at startup', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    const result = await generateAll(opts);
    expect(result).toEqual({ caCreated: true, issued: [...SERVICE_NAMES], kept: [] });
    for (const service of SERVICE_NAMES) {
      const id = loadWorkloadIdentity(configFor(dir, service), opts.clock);
      expect(id.spiffeId).toBe(`spiffe://bastion.local/services/${service}`);
    }
  });

  posixOnly('writes private keys 0600 and certificates 0644', async () => {
    const dir = tmpVar();
    await generateAll(testOptions(dir));
    const p = pkiPaths(dir);
    expect(mode(p.caKey)).toBe(0o600);
    expect(mode(p.serviceKey('payments'))).toBe(0o600);
    expect(mode(p.caCert)).toBe(0o644);
    expect(mode(p.serviceCert('payments'))).toBe(0o644);
  });

  it('lets only edge answer to localhost', async () => {
    const dir = tmpVar();
    await generateAll(testOptions(dir));
    const p = pkiPaths(dir);
    const san = (s: 'edge' | 'orders') => new X509Certificate(read(p.serviceCert(s))).subjectAltName;
    expect(san('edge')).toContain('DNS:localhost');
    expect(san('edge')).toContain('IP Address:127.0.0.1');
    expect(san('orders')).not.toContain('localhost');
  });

  it('is idempotent: a second run keeps everything byte-for-byte', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const before = readTree(dir);
    const again = await generateAll(opts);
    expect(again).toEqual({ caCreated: false, issued: [], kept: [...SERVICE_NAMES] });
    expect(readTree(dir)).toEqual(before);
  });

  it('re-issues certificates that are about to expire and keeps the CA', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const caBefore = read(pkiPaths(dir).caCert);
    const soon = new FakeClock(opts.clock.nowMs() + 23.5 * 3_600_000);
    const result = await generateAll({ ...opts, clock: soon });
    expect(result.issued).toEqual([...SERVICE_NAMES]);
    expect(result.caCreated).toBe(false);
    expect(read(pkiPaths(dir).caCert)).toBe(caBefore);
  });

  it('re-issues only a service whose files are broken', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    rmSync(pkiPaths(dir).serviceKey('payments'));
    const result = await generateAll(opts);
    expect(result.issued).toEqual(['payments']);
    expect(result.kept).toEqual(['edge', 'orders', 'inventory']);
  });

  it('replaces the CA and every certificate with forceCa', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const oldCa = read(pkiPaths(dir).caCert);
    const result = await generateAll(opts, { forceCa: true });
    expect(result.caCreated).toBe(true);
    expect(result.issued).toEqual([...SERVICE_NAMES]);
    expect(read(pkiPaths(dir).caCert)).not.toBe(oldCa);
    for (const service of SERVICE_NAMES) {
      expect(loadWorkloadIdentity(configFor(dir, service), opts.clock).serviceName).toBe(service);
    }
  });

  it('refuses an expired CA and incomplete CA files rather than guessing', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const later = new FakeClock(opts.clock.nowMs() + 31 * DAY);
    await expect(generateAll({ ...opts, clock: later })).rejects.toThrow(/validity window/);
    rmSync(pkiPaths(dir).caKey);
    await expect(generateAll(opts)).rejects.toThrow(/incomplete/);
  });

  it('rejects a trust domain that is not a valid SPIFFE trust domain', async () => {
    const dir = tmpVar();
    await expect(generateAll(testOptions(dir, { trustDomain: 'Bad Domain' }))).rejects.toThrow(
      ConfigError,
    );
  });

  it('is byte-identical across runs with the same seed and clock, and differs otherwise', async () => {
    const clock = () => new FakeClock(Date.UTC(2026, 9, 12, 12, 0, 0));
    const run = async (seed: string) => {
      const dir = tmpVar();
      await generateAll(testOptions(dir, { random: new SeededRandom(seed), clock: clock() }));
      return readTree(dir);
    };
    const a = await run('seed-1');
    expect(Object.keys(a)).toHaveLength(1 + 1 + 2 * SERVICE_NAMES.length);
    expect(await run('seed-1')).toEqual(a);
    expect(await run('seed-2')).not.toEqual(a);
  });
});

describe('generated material over real mTLS', () => {
  it('lets edge call orders, and the client verifies orders by SPIFFE ID', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const p = pkiPaths(dir);
    const server = await startOrdersServer(dir, opts.clock);
    const reply = await mtlsCall(server.port, {
      cert: p.serviceCert('edge'),
      key: p.serviceKey('edge'),
      ca: p.caCert,
    });
    await server.close();
    expect(reply.status).toBe(200);
    expect(reply.body).toMatchObject({ ok: true, identity: { service: 'edge' } });
  });

  it('turns away inventory: a valid service that is not allowed to call orders', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const p = pkiPaths(dir);
    const server = await startOrdersServer(dir, opts.clock);
    const reply = await mtlsCall(server.port, {
      cert: p.serviceCert('inventory'),
      key: p.serviceKey('inventory'),
      ca: p.caCert,
    });
    await server.close();
    expect(reply.status).toBe(401);
    expect(reply.body).toMatchObject({ reason: 'mtls+bad-identity', identity: { service: 'inventory' } });
  });
});
