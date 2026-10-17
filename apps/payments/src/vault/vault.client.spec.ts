import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { VaultClient, VaultUnavailableError } from './vault.client';
import type { VaultConfig } from '../../../../libs/bastion-common/src/config/config';

async function withServer(
  handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
  fn: (addr: string) => Promise<void>,
): Promise<void> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = (server.address() as AddressInfo).port;
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const cfg = (addr: string): VaultConfig => ({
  addr,
  roleIdFile: '/dev/null',
  wrappedSecretIdFile: '/dev/null',
  keyTtlSeconds: 10,
});

describe('VaultClient.login', () => {
  it('POSTs role_id and secret_id and returns the token', async () => {
    let body = '';
    await withServer(
      (req, res) => {
        req.on('data', (c: Buffer) => (body += c.toString('utf8')));
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ auth: { client_token: 'tok', lease_duration: 3600 } }));
        });
      },
      async (addr) => {
        const r = await new VaultClient(cfg(addr)).login('r', 's');
        expect(r.token).toBe('tok');
        expect(r.leaseDurationSeconds).toBe(3600);
        expect(JSON.parse(body)).toEqual({ role_id: 'r', secret_id: 's' });
      },
    );
  });

  it('throws VaultUnavailableError on a missing client_token', async () => {
    await withServer(
      (_, res) => {
        res.writeHead(200).end('{}');
      },
      async (addr) => {
        await expect(new VaultClient(cfg(addr)).login('r', 's')).rejects.toThrow(VaultUnavailableError);
      },
    );
  });

  it('throws on 403', async () => {
    await withServer(
      (_, res) => {
        res.writeHead(403).end('nope');
      },
      async (addr) => {
        await expect(new VaultClient(cfg(addr)).login('r', 's')).rejects.toThrow(/Vault returned 403/);
      },
    );
  });

  it('throws VaultUnavailableError when the address is unreachable', async () => {
    await expect(new VaultClient(cfg('http://127.0.0.1:1')).login('r', 's')).rejects.toThrow(
      VaultUnavailableError,
    );
  });
});

describe('VaultClient.randomBytes', () => {
  it('requests the byte count in the path and decodes hex', async () => {
    await withServer(
      (req, res) => {
        expect(req.method).toBe('GET');
        expect(req.url).toBe('/v1/sys/tools/random/8');
        expect(req.headers['x-vault-token']).toBe('tok');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ data: { random_bytes: 'deadbeef00ffeedd' } }));
      },
      async (addr) => {
        const bytes = await new VaultClient(cfg(addr)).randomBytes('tok', 8);
        expect(bytes.toString('hex')).toBe('deadbeef00ffeedd');
      },
    );
  });

  it('rejects a response with the wrong length', async () => {
    await withServer(
      (_, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ data: { random_bytes: 'deadbeef' } }));
      },
      async (addr) => {
        await expect(new VaultClient(cfg(addr)).randomBytes('tok', 8)).rejects.toThrow(
          /unexpected shape/,
        );
      },
    );
  });

  it('rejects bytes out of range', async () => {
    await expect(new VaultClient(cfg('http://127.0.0.1:1')).randomBytes('tok', 0)).rejects.toThrow(
      RangeError,
    );
  });
});
