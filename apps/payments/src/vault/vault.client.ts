import type { VaultConfig } from '@bastion/common';

/** The Vault could not be reached, or answered with an error. Fail closed. */
export class VaultUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultUnavailableError';
  }
}

interface AppRoleLoginResponse {
  readonly auth?: { readonly client_token?: unknown; readonly lease_duration?: unknown };
}

interface RandomResponse {
  readonly data?: { readonly random_bytes?: unknown };
}

export interface AppRoleSession {
  readonly token: string;
  readonly leaseDurationSeconds: number;
}

/**
 * Minimal Vault client: AppRole login and `sys/tools/random`.
 *
 * Two calls, both over plain HTTP against the dev Vault on the internal
 * `bastion-vault` network. Timeouts are bounded and redirects are refused, so
 * a hostile or misconfigured Vault can only make calls fail, never hang or
 * redirect.
 */
export class VaultClient {
  constructor(private readonly cfg: VaultConfig, private readonly timeoutMs = 2_000) {}

  /**
   * POST /v1/sys/wrapping/unwrap with the wrap token, returning the
   * secret_id carried inside it. The wrapped secret_id is a one-shot
   * wrapping token, not a secret_id; it has to be unwrapped first.
   */
  async unwrapSecretId(wrapToken: string): Promise<string> {
    const body = await this.post('/v1/sys/wrapping/unwrap', {});
    // The unwrap endpoint takes the token in the header, not the body.
    // Re-run with the header.
    void body;
    const url = `${this.cfg.addr.replace(/\/+$/, '')}/v1/sys/wrapping/unwrap`;
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'x-vault-token': wrapToken, 'content-type': 'application/json' },
        body: '{}',
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: 'error',
      });
    } catch (err) {
      throw new VaultUnavailableError(
        `Vault unwrap failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!res.ok) throw new VaultUnavailableError(`Vault unwrap returned ${res.status}`);
    const parsed = (await res.json()) as { data?: { secret_id?: unknown } };
    const secret = parsed.data?.secret_id;
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new VaultUnavailableError('Vault unwrap response missing secret_id');
    }
    return secret;
  }

  /** POST /v1/auth/approle/login with the given role_id and (unwrapped) secret_id. */
  async login(roleId: string, secretId: string): Promise<AppRoleSession> {
    const body = await this.post('/v1/auth/approle/login', { role_id: roleId, secret_id: secretId });
    const parsed = body as AppRoleLoginResponse;
    const token = parsed.auth?.client_token;
    const lease = parsed.auth?.lease_duration;
    if (typeof token !== 'string' || token.length === 0) {
      throw new VaultUnavailableError('Vault login response missing client_token');
    }
    return {
      token,
      leaseDurationSeconds: typeof lease === 'number' && Number.isFinite(lease) ? lease : 0,
    };
  }

  /** GET /v1/sys/tools/random/:n, returning exactly `bytes` random bytes. */
  async randomBytes(token: string, bytes: number): Promise<Buffer> {
    if (!Number.isInteger(bytes) || bytes < 1 || bytes > 4096) {
      throw new RangeError('bytes must be an integer between 1 and 4096');
    }
    const path = `/v1/sys/tools/random/${bytes}`;
    const res = await this.request(path, { method: 'POST', headers: { 'x-vault-token': token } });
    const parsed = res as RandomResponse;
    // Vault's sys/tools/random returns the bytes base64-encoded (not hex).
    const encoded = parsed.data?.random_bytes;
    if (typeof encoded !== 'string' || encoded.length === 0) {
      throw new VaultUnavailableError('Vault random response has an unexpected shape');
    }
    const decoded = Buffer.from(encoded, 'base64');
    if (decoded.length !== bytes) {
      throw new VaultUnavailableError(
        `Vault random returned ${decoded.length} bytes, expected ${bytes}`,
      );
    }
    return decoded;
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  private async request(path: string, init: RequestInit): Promise<unknown> {
    const url = `${this.cfg.addr.replace(/\/+$/, '')}${path}`;
    let res: Response;
    try {
      res = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: 'error',
      });
    } catch (err) {
      throw new VaultUnavailableError(
        `Vault request failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (!res.ok) throw new VaultUnavailableError(`Vault returned ${res.status}`);
    try {
      return (await res.json()) as unknown;
    } catch {
      throw new VaultUnavailableError('Vault response is not valid JSON');
    }
  }
}
