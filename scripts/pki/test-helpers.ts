import * as https from 'node:https';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { FakeClock, type Clock } from '../../libs/bastion-common/src/clock/clock';
import type { BastionConfig, ServiceName } from '../../libs/bastion-common/src/config/config';
import { checkPeer } from '../../libs/bastion-common/src/identity/peer-check';
import { spiffeIdFor } from '../../libs/bastion-common/src/identity/spiffe';
import { buildMtlsConnectOptions } from '../../libs/bastion-common/src/mtls/client';
import { readTlsMaterial } from '../../libs/bastion-common/src/mtls/cert-material';
import { mtlsServerOptions } from '../../libs/bastion-common/src/mtls/server-options';
import {
  attachTlsClientErrorHandler,
  type TlsRejection,
} from '../../libs/bastion-common/src/mtls/tls-errors';
import { SeededRandom } from '../../libs/bastion-common/src/random/random-source';
import type { PkiOptions } from './cli-options';
import { pkiPaths } from './layout';

/** A fresh temporary var/ directory. */
export function tmpVar(): string {
  return mkdtempSync(join(tmpdir(), 'bastion-pki-'));
}

/** Deterministic options: seeded randomness and a clock set to real "now" by default. */
export function testOptions(varDir: string, over: Partial<PkiOptions> = {}): PkiOptions {
  return {
    varDir,
    trustDomain: 'bastion.local',
    random: new SeededRandom('test-seed'),
    clock: new FakeClock(Date.now()),
    certTtlHours: 24,
    caTtlDays: 30,
    renewWindowMs: 3_600_000,
    ...over,
  };
}

/** The slice of BastionConfig that loadWorkloadIdentity needs, pointing at generated files. */
export function configFor(varDir: string, service: ServiceName) {
  const p = pkiPaths(varDir);
  return {
    serviceName: service,
    trustDomain: 'bastion.local',
    tls: { certFile: p.serviceCert(service), keyFile: p.serviceKey(service), caFile: p.caCert },
  } satisfies Pick<BastionConfig, 'serviceName' | 'trustDomain' | 'tls'>;
}

/**
 * Every file under `dir` keyed by relative path, for byte-for-byte comparisons.
 * Keys always use POSIX "/" separators so the same assertions hold on Windows
 * and POSIX, where `path.relative` uses different separators.
 */
export function readTree(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string): void => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else out[relative(dir, full).split(/[\\/]/).join('/')] = readFileSync(full, 'utf8');
    }
  };
  walk(dir);
  return out;
}

export interface TestServer {
  readonly port: number;
  readonly rejections: TlsRejection[];
  close(): Promise<void>;
}

/** Starts an mTLS server using the generated orders material that admits only edge. */
export async function startOrdersServer(varDir: string, clock: Clock): Promise<TestServer> {
  const paths = pkiPaths(varDir);
  const material = readTlsMaterial({
    certFile: paths.serviceCert('orders'),
    keyFile: paths.serviceKey('orders'),
    caFile: paths.caCert,
  });
  const allowedIds = [spiffeIdFor('bastion.local', 'edge')];
  const server = https.createServer(mtlsServerOptions(material), (req, res) => {
    const cert = (req.socket as TLSSocket).getPeerCertificate();
    const check = checkPeer({ cert, clock, allowedIds });
    res.writeHead(check.ok ? 200 : 401, { 'content-type': 'application/json' });
    res.end(JSON.stringify(check));
  });
  const rejections: TlsRejection[] = [];
  attachTlsClientErrorHandler(server, (r) => void rejections.push(r));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return { port, rejections, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

export interface CallFiles {
  readonly cert?: string;
  readonly key?: string;
  readonly ca: string;
}

/** Calls the test server over mTLS using PEM files; resolves with status and parsed body. */
export function mtlsCall(
  port: number,
  files: CallFiles,
  expectedServerId = spiffeIdFor('bastion.local', 'orders'),
): Promise<{ status: number; body: Record<string, unknown> }> {
  const material = {
    cert: Buffer.from(files.cert ? readFileSync(files.cert) : ''),
    key: Buffer.from(files.key ? readFileSync(files.key) : ''),
    ca: readFileSync(files.ca),
  };
  const connect = buildMtlsConnectOptions({ material, expectedServerId, connectTimeoutMs: 3000 });
  const opts = files.cert ? connect : { ...connect, cert: undefined, key: undefined };
  return new Promise((resolve, reject) => {
    const req = https.request({ ...opts, host: '127.0.0.1', port, path: '/', agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () =>
        resolve({
          status: res.statusCode ?? 0,
          body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>,
        }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

/** Waits (up to ~2s) for the server to record `count` handshake rejections. */
export async function waitForRejections(server: TestServer, count: number): Promise<void> {
  for (let i = 0; i < 100 && server.rejections.length < count; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
}
