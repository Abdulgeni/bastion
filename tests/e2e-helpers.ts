import { createServer } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import https from 'node:https';
import type { BastionConfig, ServiceName } from '../libs/bastion-common/src/config/config';
import { SERVICE_NAMES } from '../libs/bastion-common/src/config/config';
import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import { bootstrapService, type RunningService } from '../libs/bastion-common/src/nest/bootstrap';
import { generateAll } from '../scripts/gen-certs';
import { ensureJwtKeyRing } from '../scripts/rotate-jwt';
import { testOptions, tmpVar } from '../scripts/pki/test-helpers';
import { EdgeAppModule } from '../apps/edge/src/app.module';
import { OrdersAppModule } from '../apps/orders/src/app.module';
import { InventoryAppModule } from '../apps/inventory/src/app.module';
import { PaymentsAppModule } from '../apps/payments/src/app.module';
import { makeFakeVaultClient } from './fake-vault';

export interface Ports {
  readonly edge: { readonly data: number; readonly mgmt: number };
  readonly orders: { readonly data: number; readonly mgmt: number };
  readonly inventory: { readonly data: number; readonly mgmt: number };
  readonly payments: { readonly data: number; readonly mgmt: number };
}

export interface Stack {
  readonly varDir: string;
  readonly ports: Ports;
  close(): Promise<void>;
}

export async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

export async function allocatePorts(): Promise<Ports> {
  const [edgeData, edgeMgmt, ordersData, ordersMgmt, inventoryData, inventoryMgmt, paymentsData, paymentsMgmt] =
    await Promise.all([
      freePort(), freePort(), freePort(), freePort(),
      freePort(), freePort(), freePort(), freePort(),
    ]);
  return {
    edge: { data: edgeData, mgmt: edgeMgmt },
    orders: { data: ordersData, mgmt: ordersMgmt },
    inventory: { data: inventoryData, mgmt: inventoryMgmt },
    payments: { data: paymentsData, mgmt: paymentsMgmt },
  };
}

export function buildConfig(service: ServiceName, ports: Ports, varDir: string): BastionConfig {
  const base: BastionConfig = {
    serviceName: service,
    nodeEnv: 'test',
    trustDomain: 'bastion.local',
    logLevel: 'silent',
    data: { host: '127.0.0.1', port: ports[service].data },
    mgmt: { host: '127.0.0.1', port: ports[service].mgmt },
    tls: {
      certFile: join(varDir, 'certs', service, 'cert.pem'),
      keyFile: join(varDir, 'certs', service, 'key.pem'),
      caFile: join(varDir, 'ca', 'ca.pem'),
    },
    auditDir: join(varDir, 'audit'),
    jwt: {
      jwksUrl: `http://127.0.0.1:${ports.edge.mgmt}/.well-known/jwks.json`,
      replayCacheSize: 1000,
      keyStoreDir: join(varDir, 'jwt'),
    },
    isEdge: service === 'edge',
    serviceUrls: {
      edge: `https://127.0.0.1:${ports.edge.data}`,
      orders: `https://127.0.0.1:${ports.orders.data}`,
      inventory: `https://127.0.0.1:${ports.inventory.data}`,
      payments: `https://127.0.0.1:${ports.payments.data}`,
    },
  };
  // Payments additionally needs a Vault section. Populated here even though the
  // e2e overrides the client, because `loadConfig` would populate it for the real
  // binary and the module factory asserts on its presence.
  if (service === 'payments') {
    return {
      ...base,
      vault: {
        addr: 'http://127.0.0.1:1',  // unreachable; the fake client ignores it
        roleIdFile: join(varDir, 'vault', 'role-id'),
        wrappedSecretIdFile: join(varDir, 'vault', 'wrapped-secret-id'),
        keyTtlSeconds: 10,
      },
    };
  }
  return base;
}

function appModuleFor(service: ServiceName, config: BastionConfig): unknown {
  switch (service) {
    case 'edge':
      return EdgeAppModule.forRoot(config);
    case 'orders':
      return OrdersAppModule.forRoot(config);
    case 'inventory':
      return InventoryAppModule.forRoot(config);
    case 'payments':
      return PaymentsAppModule.forRoot(config, {
        vaultClient: makeFakeVaultClient(),
        appRole: { roleId: 'test-role', secretId: 'test-secret' },
      });
  }
}

export async function startService(
  service: ServiceName,
  config: BastionConfig,
): Promise<RunningService> {
  try {
    return await bootstrapService({ config, appModule: appModuleFor(service, config) as never });
  } catch (err) {
    process.stderr.write(
      `[e2e] ${service} failed to start: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
    );
    throw err;
  }
}

export async function startAll(): Promise<Stack> {
  const varDir = tmpVar();
  const clock = new FakeClock(Date.now());
  await generateAll(testOptions(varDir, { clock }));
  ensureJwtKeyRing(testOptions(varDir, { clock }));
  const ports = await allocatePorts();
  const services: RunningService[] = [];
  for (const service of SERVICE_NAMES) {
    services.push(await startService(service, buildConfig(service, ports, varDir)));
  }
  return {
    varDir,
    ports,
    close: async () => {
      for (const s of services) await s.close().catch(() => undefined);
    },
  };
}

export interface EdgeRequestOptions {
  readonly caPem: string;
  readonly port: number;
  readonly path: string;
  readonly body?: unknown;
  readonly token?: string;
}

export function edgePost(opts: EdgeRequestOptions): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const payload = opts.body === undefined ? '' : JSON.stringify(opts.body);
    const req = https.request(
      {
        host: '127.0.0.1',
        port: opts.port,
        path: opts.path,
        method: 'POST',
        ca: [opts.caPem],
        rejectUnauthorized: true,
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
          ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
        },
        timeout: 5_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          const body = text.length > 0 ? (JSON.parse(text) as unknown) : undefined;
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('edge request timeout')));
    req.end(payload);
  });
}

export function readAudit(varDir: string): Record<ServiceName, Record<string, unknown>[]> {
  const out = {} as Record<ServiceName, Record<string, unknown>[]>;
  for (const service of SERVICE_NAMES) {
    const path = join(varDir, 'audit', `${service}.log`);
    const text = existsSync(path) ? readFileSync(path, 'utf8') : '';
    out[service] = text
      .split('\n')
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }
  return out;
}

export function diffAudit(
  before: Record<ServiceName, Record<string, unknown>[]>,
  after: Record<ServiceName, Record<string, unknown>[]>,
): Record<ServiceName, Record<string, unknown>[]> {
  const out = {} as Record<ServiceName, Record<string, unknown>[]>;
  for (const service of SERVICE_NAMES) out[service] = after[service].slice(before[service].length);
  return out;
}
