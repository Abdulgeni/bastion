import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SystemClock } from '../libs/bastion-common/src/clock/clock';
import { JwtKeyStore } from '../libs/bastion-common/src/jwt/key-store';
import { TokenIssuer } from '../libs/bastion-common/src/jwt/issuer';
import { SeededRandom } from '../libs/bastion-common/src/random/random-source';
import { tamperPayload } from '../scripts/forge-token';
import { diffAudit, edgePost, readAudit, startAll, type Stack } from './e2e-helpers';

jest.setTimeout(60_000);

let stack: Stack;
let caPem: string;

beforeAll(async () => {
  stack = await startAll();
  caPem = readFileSync(join(stack.varDir, 'ca', 'ca.pem'), 'utf8');
});

afterAll(async () => {
  if (stack) await stack.close();
});

/** Logs in as alice and returns the token. */
async function login(): Promise<string> {
  const r = await edgePost({
    caPem,
    port: stack.ports.edge.data,
    path: '/login',
    body: { username: 'alice', password: 'hunter2' },
  });
  expect(r.status).toBe(201);
  const token = (r.body as { token?: string }).token;
  expect(typeof token).toBe('string');
  return token as string;
}

describe('end to end: happy path', () => {
  it('logs in at edge and places one order end to end', async () => {
    const before = readAudit(stack.varDir);
    const token = await login();
    const r = await edgePost({
      caPem,
      port: stack.ports.edge.data,
      path: '/orders',
      body: { sku: 'sku-1', quantity: 1, amount: 100 },
      token,
    });
    expect(r.status).toBe(201);
    const body = r.body as { order_id?: string; inventory?: { reserved?: boolean }; payment?: { keyFingerprint?: string } };
    expect(typeof body.order_id).toBe('string');
    expect(body.inventory?.reserved).toBe(true);
    expect(typeof body.payment?.keyFingerprint).toBe('string');

    const added = diffAudit(before, readAudit(stack.varDir));
    const allows = Object.values(added)
      .flat()
      .filter((e) => e.event === 'access' && e.decision === 'allow');
    expect(allows).toHaveLength(4);
    const jtis = new Set(allows.map((e) => e.jwt_jti));
    expect(jtis.size).toBe(1);
    const resources = allows.map((e) => e.resource).sort();
    expect(resources).toEqual(['POST /charge', 'POST /orders', 'POST /orders', 'POST /reserve']);
  });
});

describe('end to end: replay', () => {
  it('rejects the second use of the same token at edge', async () => {
    const token = await login();
    const first = await edgePost({
      caPem,
      port: stack.ports.edge.data,
      path: '/orders',
      body: { sku: 'sku-1', quantity: 1, amount: 100 },
      token,
    });
    expect(first.status).toBe(201);
    const second = await edgePost({
      caPem,
      port: stack.ports.edge.data,
      path: '/orders',
      body: { sku: 'sku-1', quantity: 1, amount: 100 },
      token,
    });
    expect(second.status).toBe(401);
  });
});

describe('end to end: bad audience', () => {
  it('rejects a genuinely signed token whose audience excludes orders', async () => {
    const store = await JwtKeyStore.load(stack.varDir);
    const issuer = new TokenIssuer(store, new SystemClock(), new SeededRandom('e2e-forge'));
    // The forged token must satisfy edge's own @RequireScope('orders:write')
    // so it reaches orders. Orders then rejects it on aud because it is
    // addressed only to payments.
    const { token } = await issuer.issue({
      subject: 'eve',
      audience: ['payments'],
      scope: ['orders:write', 'payments:charge'],
    });
    const r = await edgePost({
      caPem,
      port: stack.ports.edge.data,
      path: '/orders',
      body: { sku: 'sku-1', quantity: 1, amount: 100 },
      token,
    });
    expect(r.status).toBe(401);
  });
});

describe('end to end: tampered payload', () => {
  it('rejects a token whose payload was edited after signing', async () => {
    const token = await login();
    const tampered = tamperPayload(token, { aud: ['payments'] });
    const r = await edgePost({
      caPem,
      port: stack.ports.edge.data,
      path: '/orders',
      body: { sku: 'sku-1', quantity: 1, amount: 100 },
      token: tampered,
    });
    expect(r.status).toBe(401);
  });
});
