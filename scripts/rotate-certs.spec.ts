import { readFileSync } from 'node:fs';
import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import { SERVICE_NAMES } from '../libs/bastion-common/src/config/config';
import { loadWorkloadIdentity } from '../libs/bastion-common/src/identity/workload-identity';
import { generateAll } from './gen-certs';
import { pkiPaths } from './pki/layout';
import {
  configFor,
  mtlsCall,
  startOrdersServer,
  testOptions,
  tmpVar,
} from './pki/test-helpers';
import { rotateServiceCerts } from './rotate-certs';

const read = (path: string) => readFileSync(path, 'utf8');

describe('rotateServiceCerts', () => {
  it('replaces every service cert and key but leaves the CA byte-identical', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const p = pkiPaths(dir);
    const before = SERVICE_NAMES.map((s) => [read(p.serviceCert(s)), read(p.serviceKey(s))]);
    const ca = [read(p.caCert), read(p.caKey)];

    expect(await rotateServiceCerts(opts)).toEqual([...SERVICE_NAMES]);

    SERVICE_NAMES.forEach((s, i) => {
      expect(read(p.serviceCert(s))).not.toBe(before[i]?.[0]);
      expect(read(p.serviceKey(s))).not.toBe(before[i]?.[1]);
      expect(loadWorkloadIdentity(configFor(dir, s), opts.clock).serviceName).toBe(s);
    });
    expect([read(p.caCert), read(p.caKey)]).toEqual(ca);
  });

  it('produces certificates that still work for mTLS', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    await rotateServiceCerts(opts);
    const p = pkiPaths(dir);
    const server = await startOrdersServer(dir, opts.clock);
    const reply = await mtlsCall(server.port, {
      cert: p.serviceCert('edge'),
      key: p.serviceKey('edge'),
      ca: p.caCert,
    });
    await server.close();
    expect(reply.status).toBe(200);
  });

  it('refuses when there is no CA, and when the CA has expired', async () => {
    const empty = tmpVar();
    await expect(rotateServiceCerts(testOptions(empty))).rejects.toThrow(/no CA found/);

    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const later = new FakeClock(opts.clock.nowMs() + 31 * 86_400_000);
    await expect(rotateServiceCerts({ ...opts, clock: later })).rejects.toThrow(/validity window/);
  });
});
