import { startManagementServer, type ManagementServer } from './management-server';

const servers: ManagementServer[] = [];
afterAll(async () => {
  for (const s of servers) await s.close();
});

async function start(over: Partial<Parameters<typeof startManagementServer>[0]> = {}) {
  const errors: unknown[] = [];
  const server = await startManagementServer({
    service: 'orders',
    host: '127.0.0.1',
    port: 0,
    metrics: async () => ({
      contentType: 'text/plain; version=0.0.4',
      body: '# metrics\nfoo 1\n',
    }),
    onError: (e) => errors.push(e),
    ...over,
  });
  servers.push(server);
  const call = (path: string, method = 'GET') =>
    fetch(`http://127.0.0.1:${server.port}${path}`, { method });
  return { server, call, errors };
}

describe('management server', () => {
  it('answers /healthz 200 with named check results', async () => {
    const { call } = await start({ checks: { vault: () => true } });
    const res = await call('/healthz');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.json()).toEqual({ status: 'ok', service: 'orders', checks: { vault: 'ok' } });
  });

  it('answers 503 when any check fails or throws', async () => {
    const { call } = await start({
      checks: {
        fine: () => true,
        down: () => false,
        broken: () => {
          throw new Error('x');
        },
      },
    });
    const res = await call('/healthz');
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({
      status: 'fail',
      service: 'orders',
      checks: { fine: 'ok', down: 'fail', broken: 'fail' },
    });
  });

  it('serves the metrics text with the renderer content type', async () => {
    const { call } = await start();
    const res = await call('/metrics?ignored=1');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/plain; version=0.0.4');
    expect(await res.text()).toBe('# metrics\nfoo 1\n');
  });

  it('serves the JWKS only when a provider is given', async () => {
    const withJwks = await start({ jwks: () => ({ keys: [{ kid: 'k1' }] }) });
    const res = await withJwks.call('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('max-age=10');
    expect(await res.json()).toEqual({ keys: [{ kid: 'k1' }] });
    expect((await (await start()).call('/.well-known/jwks.json')).status).toBe(404);
  });

  it('answers 503 without details, and reports the error, when a handler fails', async () => {
    const { call, errors } = await start({
      jwks: () => {
        throw new Error('secret path /var/jwt/keys.json');
      },
    });
    const res = await call('/.well-known/jwks.json');
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain('secret');
    expect(errors).toHaveLength(1);
  });

  it('answers 404 for unknown paths and 405 (GET only) for other methods', async () => {
    const { call } = await start();
    expect((await call('/orders')).status).toBe(404);
    const post = await call('/healthz', 'POST');
    expect(post.status).toBe(405);
    expect(post.headers.get('allow')).toBe('GET');
  });

  it('binds to the requested address and stops listening on close', async () => {
    const { server } = await start();
    expect(server.port).toBeGreaterThan(0);
    await server.close();
    await expect(fetch(`http://127.0.0.1:${server.port}/healthz`)).rejects.toThrow();
  });
});
