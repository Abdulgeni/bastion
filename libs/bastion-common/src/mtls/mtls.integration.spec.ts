import type { RequestListener } from 'node:http';
import * as https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { Agent } from 'undici';
import { SystemClock } from '../clock/clock';
import { checkPeer } from '../identity/peer-check';
import { selfSignedCredential, TestPki, type TestCredential } from '../testing/test-pki';
import { buildMtlsConnectOptions, createMtlsAgent } from './client';
import { mtlsServerOptions, serverAuthOptions } from './server-options';
import { attachTlsClientErrorHandler, type TlsRejection } from './tls-errors';

const EDGE = 'spiffe://bastion.local/services/edge';
const ORDERS = 'spiffe://bastion.local/services/orders';
const PAYMENTS = 'spiffe://bastion.local/services/payments';
const HOUR = 3_600_000;

interface Reply {
  status: number;
  body: Record<string, unknown>;
}

let pki: TestPki;
let server: https.Server;
let port: number;
const rejections: TlsRejection[] = [];

const handler: RequestListener = (req, res) => {
  const cert = (req.socket as TLSSocket).getPeerCertificate();
  const check = checkPeer({ cert, clock: new SystemClock(), allowedIds: [EDGE] });
  res.writeHead(check.ok ? 200 : 401, { 'content-type': 'application/json' });
  res.end(JSON.stringify(check.ok ? { ok: true, caller: check.identity.service } : check));
};

beforeAll(async () => {
  pki = await TestPki.create();
  const orders = await pki.issue({ service: 'orders' });
  server = https.createServer(
    mtlsServerOptions({
      cert: Buffer.from(orders.cert),
      key: Buffer.from(orders.key),
      ca: Buffer.from(pki.caPem),
    }),
    handler,
  );
  attachTlsClientErrorHandler(server, (r) => void rejections.push(r));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  rejections.length = 0;
});

function call(cred: TestCredential | undefined, expectedServerId = ORDERS): Promise<Reply> {
  const material = {
    cert: Buffer.from(cred?.cert ?? ''),
    key: Buffer.from(cred?.key ?? ''),
    ca: Buffer.from(pki.caPem),
  };
  const connect = buildMtlsConnectOptions({ material, expectedServerId, connectTimeoutMs: 3000 });
  const opts = cred ? connect : { ...connect, cert: undefined, key: undefined };
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

async function nextRejection(): Promise<TlsRejection> {
  for (let i = 0; i < 100 && rejections.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  expect(rejections).toHaveLength(1);
  return rejections[0] as TlsRejection;
}

describe('mTLS listener + client over real TLS', () => {
  it('serves an allowed workload', async () => {
    const reply = await call(await pki.issue({ service: 'edge' }));
    expect(reply).toEqual({ status: 200, body: { ok: true, caller: 'edge' } });
  });

  it('lets a CA-signed cert with a foreign trust domain through the handshake, then denies it by identity', async () => {
    const rogue = await pki.issue({ service: 'rogue', uri: 'spiffe://rogue.local/services/rogue' });
    const reply = await call(rogue);
    expect(reply.status).toBe(401);
    expect(reply.body).toMatchObject({ ok: false, reason: 'mtls+bad-identity' });
  });

  it('denies a legitimate service that is not allowed on the route', async () => {
    const reply = await call(await pki.issue({ service: 'payments' }));
    expect(reply.body).toMatchObject({ reason: 'mtls+bad-identity' });
  });

  it('aborts the handshake when no client certificate is presented', async () => {
    await expect(call(undefined)).rejects.toThrow();
    // The exact OpenSSL code for a missing client cert varies by platform and
    // TLS version: Linux/macOS emit ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE,
    // while Windows and some TLS 1.3 builds emit a different alert. The reason
    // is either no_client_cert (when we can identify it) or handshake_error
    // (when we cannot). What matters is that the handshake is refused.
    const rejection = await nextRejection();
    expect(['mtls+no-client-cert', 'mtls+handshake-error']).toContain(rejection.reason);
    expect(['no_client_cert', 'handshake_error']).toContain(rejection.outcome);
  });

  it('aborts the handshake for a self-signed certificate', async () => {
    await expect(call(await selfSignedCredential('edge', EDGE))).rejects.toThrow();
    expect(await nextRejection()).toMatchObject({
      reason: 'mtls+rejected_ca',
      detail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
    });
  });

  it('aborts the handshake for a certificate from a foreign CA', async () => {
    const foreign = await TestPki.create('evil-ca');
    await expect(call(await foreign.issue({ service: 'edge' }))).rejects.toThrow();
    expect(await nextRejection()).toMatchObject({
      reason: 'mtls+rejected_ca',
      detail: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    });
  });

  it('aborts the handshake for an expired certificate', async () => {
    const now = Date.now();
    const expired = await pki.issue({
      service: 'edge',
      notBefore: new Date(now - 3 * HOUR),
      notAfter: new Date(now - HOUR),
    });
    await expect(call(expired)).rejects.toThrow();
    expect(await nextRejection()).toMatchObject({
      reason: 'mtls+expired',
      outcome: 'rejected_expired',
      detail: 'CERT_HAS_EXPIRED',
    });
  });

  it('makes the client refuse a server that presents the wrong workload identity', async () => {
    const edge = await pki.issue({ service: 'edge' });
    await expect(call(edge, PAYMENTS)).rejects.toThrow(/SPIFFE ID/);
  });
});

describe('server-auth listener (edge)', () => {
  it('serves a client that has no certificate and never asks for one', async () => {
    const edgeCred = await pki.issue({ service: 'edge' });
    const plain = https.createServer(
      serverAuthOptions({ cert: Buffer.from(edgeCred.cert), key: Buffer.from(edgeCred.key) }),
      (req, res) => {
        const cert = (req.socket as TLSSocket).getPeerCertificate();
        res.end(JSON.stringify({ peerCertKeys: Object.keys(cert).length }));
      },
    );
    await new Promise<void>((resolve) => plain.listen(0, '127.0.0.1', resolve));
    const p = (plain.address() as AddressInfo).port;
    const body = await new Promise<string>((resolve, reject) => {
      https
        .get({ host: '127.0.0.1', port: p, ca: pki.caPem, checkServerIdentity: () => undefined, agent: false }, (res) => {
          let data = '';
          res.on('data', (c: Buffer) => (data += c.toString()));
          res.on('end', () => resolve(data));
        })
        .on('error', reject);
    });
    await new Promise((resolve) => plain.close(resolve));
    expect(JSON.parse(body)).toEqual({ peerCertKeys: 0 });
  });
});

describe('createMtlsAgent', () => {
  it('returns an undici Agent', async () => {
    const cred = await pki.issue({ service: 'edge' });
    const material = { cert: Buffer.from(cred.cert), key: Buffer.from(cred.key), ca: Buffer.from(pki.caPem) };
    expect(createMtlsAgent({ material, expectedServerId: ORDERS })).toBeInstanceOf(Agent);
  });
});
