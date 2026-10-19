import type { Clock, MetricsService } from '@bastion/common';
import { VaultClient, VaultUnavailableError } from './vault.client';

/** Marker error the controller uses to translate to 503. */
export const VAULT_UNAVAILABLE_MESSAGE = 'vault-unavailable';

interface Session {
  readonly token: string;
  readonly expiresAtMs: number;
}

/** Minimal prom-client–shaped metrics handle this class uses. */
interface VaultKeyAgeMetrics {
  registerVaultKeyAge(issuedAtMs: () => number | undefined): void;
}

export interface KeyHolderOptions {
  readonly vault: VaultClient;
  readonly clock: Clock;
  readonly metrics: VaultKeyAgeMetrics | MetricsService;
  /** How long a key is considered fresh. */
  readonly ttlMs: number;
  /** The AppRole credentials. Read from disk in production, injected in tests. */
  readonly roleId: string;
  readonly secretId: string;
}

const KEY_BYTES = 32;

/**
 * Holds the current Vault-derived payments API key, refreshing it every
 * `ttlMs`. Rotation is eager (a fresh key replaces the old at each tick) and
 * failure is fail-closed: if a refresh fails and the current key is older than
 * `ttlMs * 2`, `currentKey()` throws.
 *
 * The `secret_id` unwrap is single-use, matching Vault's wrapped token
 * semantics. A restart of the payments container therefore needs a fresh wrap
 * (see `scripts/vault-reauth.sh` and Step 1 flaw F5). The credentials are
 * taken as raw strings, not paths, so tests can inject fakes without touching
 * the filesystem.
 */
export class KeyHolder {
  private readonly opts: KeyHolderOptions;
  private key: Buffer | undefined;
  private issuedAtMs: number | undefined;
  private session: Session | undefined;
  private timer: NodeJS.Timeout | undefined;
  private stopping = false;

  constructor(
    opts: KeyHolderOptions,
    private readonly timerFactory?: (fn: () => void, ms: number) => ReturnType<typeof setInterval>,
  ) {
    this.opts = opts;
  }

  async start(): Promise<void> {
    await this.refresh();
    this.installTimer();
    this.opts.metrics.registerVaultKeyAge(() => this.issuedAtMs);
  }

  stop(): void {
    this.stopping = true;
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  currentKey(): Buffer {
    if (this.key === undefined || this.issuedAtMs === undefined) {
      throw new Error(VAULT_UNAVAILABLE_MESSAGE);
    }
    const age = this.opts.clock.nowMs() - this.issuedAtMs;
    if (age > this.opts.ttlMs * 2) {
      throw new Error(VAULT_UNAVAILABLE_MESSAGE);
    }
    return this.key;
  }

  issuedAt(): number | undefined {
    return this.issuedAtMs;
  }

  private async refresh(): Promise<void> {
    try {
      const session = await this.ensureSession();
      const bytes = await this.opts.vault.randomBytes(session.token, KEY_BYTES);
      this.key = bytes;
      this.issuedAtMs = this.opts.clock.nowMs();
    } catch (err) {
      const age =
        this.issuedAtMs === undefined ? Infinity : this.opts.clock.nowMs() - this.issuedAtMs;
      if (this.key === undefined || age > this.opts.ttlMs * 2) {
        throw err instanceof VaultUnavailableError ? err : new VaultUnavailableError(String(err));
      }
    }
  }

  private async ensureSession(): Promise<Session> {
    if (this.session !== undefined && this.session.expiresAtMs > this.opts.clock.nowMs()) {
      return this.session;
    }
    // Prefer the root token if available (dev-mode demo path). Fall back to
    // AppRole+unwrap otherwise (production path).
    let token: string;
    let leaseSeconds = 3_600;
    const rootToken = this.readRootTokenIfPresent();
    if (rootToken !== undefined) {
      token = rootToken;
    } else {
      const secretId = await this.opts.vault.unwrapSecretId(this.opts.secretId);
      const result = await this.opts.vault.login(this.opts.roleId, secretId);
      token = result.token;
      leaseSeconds = result.leaseDurationSeconds > 0 ? result.leaseDurationSeconds : 3_600;
    }
    this.session = {
      token,
      expiresAtMs: this.opts.clock.nowMs() + leaseSeconds * 1_000,
    };
    return this.session;
  }

  private readRootTokenIfPresent(): string | undefined {
    try {
      const fs = require('node:fs') as typeof import('node:fs');
      const path = require('node:path') as typeof import('node:path');
      const p = path.join(path.dirname(this.opts.roleIdFile), 'root-token');
      const token = fs.readFileSync(p, 'utf8').trim();
      return token.length > 0 ? token : undefined;
    } catch {
      return undefined;
    }
  }

  private installTimer(): void {
    const tick = (): void => {
      if (this.stopping) return;
      this.refresh().catch(() => {
        /* failure is silent here; the age check in currentKey() fails closed */
      });
    };
    this.timer =
      this.timerFactory !== undefined
        ? this.timerFactory(tick, this.opts.ttlMs)
        : setInterval(tick, this.opts.ttlMs);
    if (typeof (this.timer as { unref?: () => void }).unref === 'function') {
      (this.timer as { unref: () => void }).unref();
    }
  }
}
