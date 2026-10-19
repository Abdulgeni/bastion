import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import type { DynamicModule, INestApplication, Type } from '@nestjs/common';
import * as https from 'node:https';
import type { ServerOptions } from 'node:https';
import { SystemClock } from '../clock/clock';
import { loadWorkloadIdentity, type WorkloadIdentity } from '../identity/workload-identity';
import { attachTlsClientErrorHandler } from '../mtls/tls-errors';
import { mtlsServerOptions, serverAuthOptions } from '../mtls/server-options';
import { AccessRecorder } from '../audit/access-recorder';
import { MetricsService } from '../metrics/metrics.service';
import { startManagementServer, type ManagementServer } from '../management/management-server';
import { JwtKeyStore } from '../jwt/key-store';
import { buildJwks } from '../jwt/jwks';
import type { BastionConfig } from '../config/config';

export interface BootstrapOptions {
  readonly config: BastionConfig;
  readonly appModule: Type<unknown> | DynamicModule;
}

export interface RunningService {
  readonly dataPort: number;
  readonly mgmtPort: number;
  close(): Promise<void>;
}

const TRACE = process.env.BASTION_BOOT_TRACE === '1';
const trace = (msg: string): void => {
  if (TRACE) process.stderr.write(`[boot] ${msg}\n`);
};

// Refuse to let Nest call process.exit() on bootstrap errors; surface the error instead.
process.on('uncaughtException', (e) => {
  process.stderr.write(`[boot] uncaughtException: ${e.stack ?? e.message}\n`);
  process.exit(1);
});
process.on('unhandledRejection', (e) => {
  const err = e instanceof Error ? e : new Error(String(e));
  process.stderr.write(`[boot] unhandledRejection: ${err.stack ?? err.message}\n`);
  process.exit(1);
});

function dataListenerOptions(config: BastionConfig, identity: WorkloadIdentity): ServerOptions {
  return config.isEdge
    ? serverAuthOptions(identity.material)
    : mtlsServerOptions(identity.material);
}

async function createHttpsApp(
  opts: BootstrapOptions,
  tls: ServerOptions,
): Promise<INestApplication> {
  trace('createHttpsApp: building https server');
  const httpsServer = https.createServer(tls);
  const adapter = new ExpressAdapter(httpsServer);
  trace('createHttpsApp: NestFactory.create');
  const app = await NestFactory.create(opts.appModule as never, adapter, {
    logger: false,
    abortOnError: false,
  });
  trace('createHttpsApp: returned');
  return app;
}

function wireTlsClientError(app: INestApplication): void {
  const server = app.getHttpServer() as https.Server;
  const recorder = app.get(AccessRecorder);
  attachTlsClientErrorHandler(server, (r) => recorder.onTlsRejection(r));
}

async function startMgmt(
  opts: BootstrapOptions,
  app: INestApplication,
): Promise<ManagementServer> {
  const metrics = app.get(MetricsService);
  trace(`startMgmt: host=${opts.config.mgmt.host} port=${opts.config.mgmt.port}`);
  const mgmt = await startManagementServer({
    service: opts.config.serviceName,
    host: opts.config.mgmt.host,
    port: opts.config.mgmt.port,
    metrics: () => metrics.render(),
    checks: { ready: () => true },
    ...(opts.config.isEdge ? { jwks: () => buildJwks(app.get(JwtKeyStore)) } : {}),
  });
  trace(`startMgmt: listening on port ${mgmt.port}`);
  return mgmt;
}

function installSignalHandlers(close: () => Promise<void>): void {
  let closing = false;
  const handler = (): void => {
    if (closing) return;
    closing = true;
    close().finally(() => process.exit(0));
  };
  process.once('SIGTERM', handler);
  process.once('SIGINT', handler);
}

export async function bootstrapService(opts: BootstrapOptions): Promise<RunningService> {
  trace('bootstrapService: loadWorkloadIdentity');
  const clock = new SystemClock();
  const identity = loadWorkloadIdentity(opts.config, clock);
  const tls = dataListenerOptions(opts.config, identity);
  trace('bootstrapService: createHttpsApp');
  const app = await createHttpsApp(opts, tls);
  trace('bootstrapService: app.init');
  await app.init();
  trace('bootstrapService: wireTlsClientError');
  wireTlsClientError(app);
  trace(`bootstrapService: app.listen(${opts.config.data.host}:${opts.config.data.port})`);
  await app.listen(opts.config.data.port, opts.config.data.host);
  trace('bootstrapService: app.listen returned');
  trace('bootstrapService: startMgmt');
  const mgmt = await startMgmt(opts, app);

  const close = async (): Promise<void> => {
    await mgmt.close().catch(() => undefined);
    await app.close().catch(() => undefined);
  };
  installSignalHandlers(close);
  trace('bootstrapService: done, returning handle');
  return { dataPort: opts.config.data.port, mgmtPort: mgmt.port, close };
}
