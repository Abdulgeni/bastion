import { NestFactory } from '@nestjs/core';
import type { INestApplication, Type } from '@nestjs/common';
import type { Server as HttpsServer, ServerOptions } from 'node:https';
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
  /** The app's root Nest module; typically `AppModule` from the app's own `src/`. */
  readonly appModule: Type<unknown>;
}

export interface RunningService {
  readonly dataPort: number;
  readonly mgmtPort: number;
  close(): Promise<void>;
}

/** TLS options for the data listener: server-auth for edge, mTLS for everyone else. */
function dataListenerOptions(config: BastionConfig, identity: WorkloadIdentity): ServerOptions {
  return config.isEdge
    ? serverAuthOptions(identity.material)
    : mtlsServerOptions(identity.material);
}

/** Creates the Nest app on top of HTTPS. Does not start listening yet. */
async function createHttpsApp(
  opts: BootstrapOptions,
  tls: ServerOptions,
): Promise<INestApplication> {
  return NestFactory.create(opts.appModule, {
    httpsOptions: tls as never,
    logger: false,
  });
}

/** Routes aborted handshakes through the recorder so they get audited like every other deny. */
function wireTlsClientError(app: INestApplication): void {
  const server = app.getHttpServer() as HttpsServer;
  const recorder = app.get(AccessRecorder);
  attachTlsClientErrorHandler(server, (rejection) => recorder.onTlsRejection(rejection));
}

/** Builds the management server. Edge additionally serves its public JWKS. */
async function startMgmt(
  opts: BootstrapOptions,
  app: INestApplication,
): Promise<ManagementServer> {
  const metrics = app.get(MetricsService);
  return startManagementServer({
    service: opts.config.serviceName,
    host: opts.config.mgmt.host,
    port: opts.config.mgmt.port,
    metrics: () => metrics.render(),
    checks: { ready: () => true },
    ...(opts.config.isEdge ? { jwks: () => buildJwks(app.get(JwtKeyStore)) } : {}),
  });
}

/** Installs SIGTERM/SIGINT handlers that run `close` once and exit. */
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

/**
 * Boots one Bastion service: loads the workload identity, creates the HTTPS
 * data listener with the correct TLS mode (server-auth for edge, mTLS for every
 * other service), wires the tlsClientError hook so aborted handshakes are
 * audited, starts the management server (health, metrics, and JWKS on edge),
 * installs graceful shutdown, and returns a handle with both ports and a
 * close() method.
 */
export async function bootstrapService(opts: BootstrapOptions): Promise<RunningService> {
  const clock = new SystemClock();
  const identity = loadWorkloadIdentity(opts.config, clock);
  const tls = dataListenerOptions(opts.config, identity);
  const app = await createHttpsApp(opts, tls);
  await app.init();
  wireTlsClientError(app);
  await app.listen(opts.config.data.port, opts.config.data.host);
  const mgmt = await startMgmt(opts, app);

  const close = async (): Promise<void> => {
    await mgmt.close().catch(() => undefined);
    await app.close().catch(() => undefined);
  };
  installSignalHandlers(close);
  return { dataPort: opts.config.data.port, mgmtPort: mgmt.port, close };
}
