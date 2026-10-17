import { FakeClock } from '../clock/clock';
import { MetricsService, METRIC_NAMES } from '../metrics/metrics.service';
import { AuditService, type AuditSink } from './audit.service';
import { AccessRecorder } from './access-recorder';
import type { TokenClaims } from '../jwt/claims';
import type { PeerCheck } from '../identity/peer-check';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);

const claims: TokenClaims = {
  iss: 'edge',
  sub: 'alice',
  aud: ['orders'],
  iat: 1,
  exp: 2,
  jti: 'c'.repeat(32),
  scope: ['orders:write'],
};
const ctx = {
  resource: 'POST /orders',
  traceId: 'd'.repeat(16),
  peerIdentity: 'spiffe://bastion.local/services/edge',
  remoteAddr: '10.0.0.5',
};
const edgeId = {
  uri: 'spiffe://bastion.local/services/edge',
  trustDomain: 'bastion.local',
  service: 'edge',
};

function setup(service = 'orders') {
  const lines: string[] = [];
  const sink: AuditSink = { write: (l) => lines.push(l) };
  const clock = new FakeClock(NOW);
  const audit = new AuditService({ service, clock, sinks: [sink] });
  const metrics = new MetricsService(service, clock);
  const recorder = new AccessRecorder(audit, metrics);
  const events = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);
  const sample = async (name: string, labels: Record<string, string> = {}) => {
    const body = (await metrics.render()).body;
    for (const line of body.split('\n')) {
      const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})? (\S+)$/.exec(line);
      if (!m || m[1] !== name) continue;
      const got = Object.fromEntries(
        [...(m[2] ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((x) => [x[1], x[2]]),
      );
      if (Object.entries(labels).every(([k, v]) => got[k] === v)) return Number(m[3]);
    }
    return undefined;
  };
  return { recorder, events, sample };
}

describe('AccessRecorder: transport decisions', () => {
  it('counts an accepted identity check without writing an audit line', async () => {
    const o = setup();
    const check: PeerCheck = { ok: true, identity: edgeId as never };
    o.recorder.onPeerDecision({ resource: 'POST /orders', check });
    expect(o.events()).toHaveLength(0);
    expect(await o.sample(METRIC_NAMES.MTLS, { outcome: 'accepted' })).toBe(1);
  });

  it('audits a denied identity, naming who it claimed to be', async () => {
    const o = setup();
    const rogue = {
      uri: 'spiffe://rogue.local/services/rogue',
      trustDomain: 'rogue.local',
      service: 'rogue',
    };
    o.recorder.onPeerDecision({
      resource: 'POST /charge',
      check: { ok: false, reason: 'mtls+bad-identity', identity: rogue as never },
    });
    expect(o.events()[0]).toMatchObject({
      event: 'access',
      decision: 'deny',
      reason: 'mtls+bad-identity',
      resource: 'POST /charge',
      peer_identity: 'spiffe://rogue.local/services/rogue',
      status: 401,
    });
    expect(await o.sample(METRIC_NAMES.MTLS, { outcome: 'rejected_identity' })).toBe(1);
    expect(await o.sample(METRIC_NAMES.AUTHZ, { decision: 'deny', resource: 'POST /charge' })).toBe(1);
  });

  it('records a missing certificate without inventing an identity', () => {
    const o = setup();
    o.recorder.onPeerDecision({
      resource: 'GET /x',
      check: { ok: false, reason: 'mtls+no-client-cert' },
    });
    expect('peer_identity' in (o.events()[0] ?? {})).toBe(false);
  });

  it('audits an aborted handshake with its cause and remote address', async () => {
    const o = setup();
    o.recorder.onTlsRejection({
      reason: 'mtls+rejected_ca',
      outcome: 'rejected_ca',
      detail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
      remoteAddress: '172.20.0.9',
    });
    expect(o.events()[0]).toMatchObject({
      event: 'handshake',
      decision: 'deny',
      reason: 'mtls+rejected_ca',
      detail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
      remote_addr: '172.20.0.9',
    });
    expect(await o.sample(METRIC_NAMES.MTLS, { outcome: 'rejected_ca' })).toBe(1);
  });
});

describe('AccessRecorder: token decisions', () => {
  it('audits a replay with the verified subject and jti, and counts it', async () => {
    const o = setup();
    o.recorder.jwtDenied(ctx, { ok: false, reason: 'jwt+replayed' } as never);
    expect(o.events()[0]).toMatchObject({
      event: 'access',
      decision: 'deny',
      reason: 'jwt+replayed',
      status: 401,
      trace_id: 'd'.repeat(16),
      peer_identity: 'spiffe://bastion.local/services/edge',
      remote_addr: '10.0.0.5',
    });
    expect(await o.sample(METRIC_NAMES.JWT, { outcome: 'replayed' })).toBe(1);
  });

  it('attributes a scope denial to the verified subject', async () => {
    const o = setup();
    o.recorder.scopeDenied(ctx, claims, 'scope+missing:payments:charge');
    expect(o.events()[0]).toMatchObject({
      decision: 'deny',
      reason: 'scope+missing:payments:charge',
      status: 403,
      user_sub: 'alice',
    });
    expect(await o.sample(METRIC_NAMES.JWT, { outcome: 'ok' })).toBe(1);
  });

  it('audits an allowed request with everything needed to follow it across services', async () => {
    const o = setup();
    o.recorder.allowed(ctx, claims);
    expect(o.events()[0]).toMatchObject({
      event: 'access',
      decision: 'allow',
      reason: 'ok',
      resource: 'POST /orders',
      user_sub: 'alice',
      jwt_jti: 'c'.repeat(32),
      trace_id: 'd'.repeat(16),
    });
    expect(await o.sample(METRIC_NAMES.AUTHZ, { decision: 'allow', resource: 'POST /orders' })).toBe(1);
  });
});
