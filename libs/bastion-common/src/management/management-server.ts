import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

type Check = () => boolean | Promise<boolean>;

export interface ManagementOptions {
  readonly service: string;
  readonly host: string;
  readonly port: number;
  /** Renders the Prometheus text exposition. */
  readonly metrics: () => Promise<{ readonly contentType: string; readonly body: string }>;
  /** Named health checks. Any check returning false (or throwing) makes /healthz answer 503. */
  readonly checks?: Readonly<Record<string, Check>>;
  /** Edge only: provides the public JWKS document served at /.well-known/jwks.json. */
  readonly jwks?: () => unknown;
  /** Called with errors from handlers; the response never contains error details. */
  readonly onError?: (err: unknown) => void;
}

export interface ManagementServer {
  readonly port: number;
  close(): Promise<void>;
}

function send(res: ServerResponse, status: number, type: string, body: string, extra = {}): void {
  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    ...extra,
  });
  res.end(body);
}

const json = (res: ServerResponse, status: number, value: unknown, extra = {}): void =>
  send(res, status, 'application/json', JSON.stringify(value), extra);

async function runChecks(
  checks: Readonly<Record<string, Check>>,
): Promise<Record<string, 'ok' | 'fail'>> {
  const out: Record<string, 'ok' | 'fail'> = {};
  for (const [name, check] of Object.entries(checks)) {
    try {
      out[name] = (await check()) ? 'ok' : 'fail';
    } catch {
      out[name] = 'fail';
    }
  }
  return out;
}

async function health(opts: ManagementOptions, res: ServerResponse): Promise<void> {
  const checks = await runChecks(opts.checks ?? {});
  const ok = Object.values(checks).every((v) => v === 'ok');
  json(
    res,
    ok ? 200 : 503,
    { status: ok ? 'ok' : 'fail', service: opts.service, checks },
    { 'cache-control': 'no-store' },
  );
}

async function route(
  opts: ManagementOptions,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  if (req.method !== 'GET') {
    json(res, 405, { error: 'method not allowed' }, { allow: 'GET' });
    return;
  }
  const path = (req.url ?? '').split('?')[0];
  if (path === '/healthz') {
    await health(opts, res);
    return;
  }
  if (path === '/metrics') {
    const m = await opts.metrics();
    send(res, 200, m.contentType, m.body, { 'cache-control': 'no-store' });
    return;
  }
  if (path === '/.well-known/jwks.json' && opts.jwks) {
    json(res, 200, opts.jwks(), { 'cache-control': 'max-age=10' });
    return;
  }
  json(res, 404, { error: 'not found' });
}

/**
 * Starts the plain-HTTP management listener (health, metrics, and for edge
 * the JWKS). It is unauthenticated by design and must only be reachable on
 * the internal management network. It serves GET only and exposes no
 * data-plane functionality.
 */
export async function startManagementServer(opts: ManagementOptions): Promise<ManagementServer> {
  const server = createServer((req, res) => {
    route(opts, req, res).catch((err: unknown) => {
      opts.onError?.(err);
      if (!res.headersSent) json(res, 503, { error: 'unavailable' });
    });
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, opts.host, resolve);
  });
  return {
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
