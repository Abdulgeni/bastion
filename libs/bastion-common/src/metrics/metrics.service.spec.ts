import { FakeClock } from '../clock/clock';
import { METRIC_NAMES, MetricsService } from './metrics.service';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const text = async (m: MetricsService) => (await m.render()).body;

/** Finds `name{labels...} value` in Prometheus text, ignoring label order. */
function parseSample(input: string, name: string, labels: Record<string, string>): number | undefined {
  for (const line of input.split('\n')) {
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})? (\S+)$/.exec(line);
    if (!m || m[1] !== name) continue;
    const got = Object.fromEntries([...(m[2] ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((x) => [x[1], x[2]]));
    if (Object.entries(labels).every(([k, v]) => got[k] === v)) return Number(m[3]);
  }
  return undefined;
}

describe('MetricsService', () => {
  it('exports every known outcome at zero, labelled with the service', async () => {
    const body = await text(new MetricsService('orders', new FakeClock(NOW)));
    for (const outcome of ['accepted', 'rejected_ca', 'rejected_identity', 'rejected_expired', 'no_client_cert', 'handshake_error']) {
      expect(parseSample(body, METRIC_NAMES.MTLS, { outcome, service: 'orders' })).toBe(0);
    }
    for (const outcome of ['ok', 'expired', 'bad_aud', 'replayed', 'bad_sig', 'malformed']) {
      expect(parseSample(body, METRIC_NAMES.JWT, { outcome, service: 'orders' })).toBe(0);
    }
  });

  it('counts handshakes, JWT validations and authorization decisions', async () => {
    const m = new MetricsService('payments', new FakeClock(NOW));
    m.recordHandshake('rejected_ca');
    m.recordHandshake('rejected_ca');
    m.recordJwt('replayed');
    m.recordAuthz('deny', 'POST /charge');
    m.recordAuthz('allow', 'POST /charge');
    m.recordAuthz('allow', 'POST /charge');
    const body = await text(m);
    expect(parseSample(body, METRIC_NAMES.MTLS, { outcome: 'rejected_ca' })).toBe(2);
    expect(parseSample(body, METRIC_NAMES.JWT, { outcome: 'replayed' })).toBe(1);
    expect(parseSample(body, METRIC_NAMES.AUTHZ, { decision: 'allow', resource: 'POST /charge' })).toBe(2);
    expect(parseSample(body, METRIC_NAMES.AUTHZ, { decision: 'deny', resource: 'POST /charge' })).toBe(1);
  });

  it('cannot be made to create new series from untrusted resource strings', async () => {
    const m = new MetricsService('orders', new FakeClock(NOW));
    for (let i = 0; i < 50; i++) m.recordAuthz('deny', `GET /random/${i}/with space`);
    const body = await text(m);
    expect(parseSample(body, METRIC_NAMES.AUTHZ, { decision: 'deny', resource: 'other' })).toBe(50);
    expect(body).not.toContain('with space');
  });

  it('exports the Vault key age only once a key exists, computed from the Clock', async () => {
    const clock = new FakeClock(NOW);
    const m = new MetricsService('payments', clock);
      const holder: { at?: number } = {};
    m.registerVaultKeyAge(() => holder.at);
    expect(parseSample(await text(m), METRIC_NAMES.VAULT_KEY_AGE, {})).toBeUndefined();
    holder.at = NOW;
    clock.advanceMs(30_000);
    expect(parseSample(await text(m), METRIC_NAMES.VAULT_KEY_AGE, { service: 'payments' })).toBe(30);
  });

  it('is safe to create twice in one process', async () => {
    const a = new MetricsService('orders', new FakeClock(NOW));
    const b = new MetricsService('orders', new FakeClock(NOW));
    a.recordJwt('ok');
    expect(parseSample(await text(a), METRIC_NAMES.JWT, { outcome: 'ok' })).toBe(1);
    expect(parseSample(await text(b), METRIC_NAMES.JWT, { outcome: 'ok' })).toBe(0);
  });

  it('reports the Prometheus text content type', async () => {
    const r = await new MetricsService('orders', new FakeClock(NOW)).render();
    expect(r.contentType).toContain('text/plain');
  });
});
