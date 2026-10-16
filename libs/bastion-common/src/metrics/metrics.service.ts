import { Counter, Gauge, Registry } from 'prom-client';
import type { Clock } from '../clock/clock';
import { resourceLabel } from '../audit/resource';
import type { JwtOutcome } from '../jwt/reasons';
import type { MtlsOutcome } from '../mtls/reasons';

/** The four metrics every service exposes on its management port. */
export const METRIC_NAMES = {
  MTLS: 'bastion_mtls_handshake_total',
  JWT: 'bastion_jwt_validation_total',
  AUTHZ: 'bastion_authz_decisions_total',
  VAULT_KEY_AGE: 'bastion_vault_key_age_seconds',
} as const;

const MTLS_OUTCOMES: readonly MtlsOutcome[] = [
  'accepted',
  'rejected_ca',
  'rejected_identity',
  'rejected_expired',
  'no_client_cert',
  'handshake_error',
];
const JWT_OUTCOMES: readonly JwtOutcome[] = [
  'ok',
  'expired',
  'bad_aud',
  'replayed',
  'bad_sig',
  'malformed',
];

export interface RenderedMetrics {
  readonly contentType: string;
  readonly body: string;
}

/**
 * Prometheus metrics for one service. It owns a private Registry (never the
 * global one), so creating it twice in one process cannot clash. All label
 * values come from fixed sets or route templates, so a hostile client cannot
 * create new time series.
 */
export class MetricsService {
  private readonly registry = new Registry();
  private readonly mtls: Counter<'outcome'>;
  private readonly jwt: Counter<'outcome'>;
  private readonly authz: Counter<'decision' | 'resource'>;
  /**
   * The Vault key age accessor, if `registerVaultKeyAge` was called. The Gauge
   * itself is created lazily on the first scrape that sees a key, so the
   * metric is genuinely absent (not `0`) before a key exists. A `0` reading is
   * indistinguishable from "no key" for a scraper, which is a false negative
   * during incidents; absence is unambiguous.
   */
  private vaultKeyAgeAccessor?: () => number | undefined;
  private vaultKeyAgeGauge?: Gauge;

  constructor(
    service: string,
    private readonly clock: Clock,
  ) {
    this.registry.setDefaultLabels({ service });
    const registers = [this.registry];
    this.mtls = new Counter({
      name: METRIC_NAMES.MTLS,
      help: 'mTLS decisions by outcome (aborted handshakes, and per-request identity checks).',
      labelNames: ['outcome'],
      registers,
    });
    this.jwt = new Counter({
      name: METRIC_NAMES.JWT,
      help: 'JWT validations by outcome.',
      labelNames: ['outcome'],
      registers,
    });
    this.authz = new Counter({
      name: METRIC_NAMES.AUTHZ,
      help: 'Final authorization decisions per request, by decision and route.',
      labelNames: ['decision', 'resource'],
      registers,
    });
    for (const outcome of MTLS_OUTCOMES) this.mtls.inc({ outcome }, 0);
    for (const outcome of JWT_OUTCOMES) this.jwt.inc({ outcome }, 0);
  }

  recordHandshake(outcome: MtlsOutcome): void {
    this.mtls.inc({ outcome });
  }

  recordJwt(outcome: JwtOutcome): void {
    this.jwt.inc({ outcome });
  }

  recordAuthz(decision: 'allow' | 'deny', resource: string): void {
    this.authz.inc({ decision, resource: resourceLabel(resource) });
  }

  /**
   * Registers the age of the current Vault-derived key (payments only). The
   * age is computed from the Clock at scrape time, and the metric is absent
   * until a key exists (see the fields above for why absence beats `0`).
   */
  registerVaultKeyAge(issuedAtMs: () => number | undefined): void {
    this.vaultKeyAgeAccessor = issuedAtMs;
  }

  private ensureVaultKeyAgeGauge(): void {
    if (this.vaultKeyAgeGauge !== undefined || this.vaultKeyAgeAccessor === undefined) return;
    const clock = this.clock;
    const accessor = this.vaultKeyAgeAccessor;
    this.vaultKeyAgeGauge = new Gauge({
      name: METRIC_NAMES.VAULT_KEY_AGE,
      help: 'Seconds since the current payments API key was minted from Vault.',
      registers: [this.registry],
      collect() {
        const issued = accessor();
        if (issued !== undefined) this.set(Math.max(0, (clock.nowMs() - issued) / 1000));
      },
    });
  }

  async render(): Promise<RenderedMetrics> {
    // Create the gauge the first time a key actually exists.
    if (this.vaultKeyAgeAccessor !== undefined && this.vaultKeyAgeGauge === undefined) {
      if (this.vaultKeyAgeAccessor() !== undefined) this.ensureVaultKeyAgeGauge();
    }
    return { contentType: this.registry.contentType, body: await this.registry.metrics() };
  }
}
