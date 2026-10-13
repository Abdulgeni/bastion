import { FakeClock } from '../clock/clock';
import { checkPeer, type PeerCertLike } from './peer-check';

const EDGE = 'spiffe://bastion.local/services/edge';
const NOON = Date.UTC(2026, 9, 12, 12, 0, 0);
const HOUR = 3_600_000;

function cert(over: Partial<PeerCertLike> = {}): PeerCertLike {
  return {
    subjectaltname: `DNS:edge, URI:${EDGE}`,
    valid_from: 'Oct 12 00:00:00 2026 GMT',
    valid_to: 'Oct 13 00:00:00 2026 GMT',
    ...over,
  };
}

function run(c: PeerCertLike | undefined, clock = new FakeClock(NOON), allowed = [EDGE]) {
  return checkPeer({ cert: c, clock, allowedIds: allowed });
}

describe('checkPeer', () => {
  it('accepts an allowed caller', () => {
    const r = run(cert());
    expect(r.ok).toBe(true);
    expect(r).toMatchObject({ identity: { service: 'edge', trustDomain: 'bastion.local' } });
  });

  it.each([undefined, {}])('reports no client cert for %p', (c) => {
    expect(run(c)).toEqual({ ok: false, reason: 'mtls+no-client-cert' });
  });

  it('rejects after valid_to and before valid_from, using the injected Clock', () => {
    expect(run(cert(), new FakeClock(NOON + 13 * HOUR))).toMatchObject({ reason: 'mtls+expired' });
    expect(run(cert(), new FakeClock(NOON - 13 * HOUR))).toMatchObject({ reason: 'mtls+expired' });
  });

  it('flips from ok to expired as the clock advances', () => {
    const clock = new FakeClock(NOON);
    expect(run(cert(), clock).ok).toBe(true);
    clock.advanceMs(24 * HOUR);
    expect(run(cert(), clock)).toMatchObject({ ok: false, reason: 'mtls+expired' });
  });

  it('treats the validity boundary as inclusive', () => {
    const end = Date.UTC(2026, 9, 13, 0, 0, 0);
    expect(run(cert(), new FakeClock(end)).ok).toBe(true);
    expect(run(cert(), new FakeClock(end + 1))).toMatchObject({ reason: 'mtls+expired' });
  });

  it('fails closed on unparseable validity dates', () => {
    expect(run(cert({ valid_from: 'garbage' }))).toMatchObject({ reason: 'mtls+bad-identity' });
    expect(run(cert({ valid_to: undefined }))).toMatchObject({ reason: 'mtls+bad-identity' });
  });

  it.each([
    ['no URI SAN', 'DNS:edge'],
    ['two URI SANs', `URI:${EDGE}, URI:spiffe://bastion.local/services/orders`],
    ['non-SPIFFE URI', 'URI:https://bastion.local/services/edge'],
    ['URI text hidden in a DNS entry', `DNS:"x, URI:${EDGE}"`],
  ])('rejects %s', (_name, san) => {
    expect(run(cert({ subjectaltname: san }))).toEqual({ ok: false, reason: 'mtls+bad-identity' });
  });

  it('rejects a CA-signed cert from a foreign trust domain, and says who it claimed to be', () => {
    const rogue = cert({ subjectaltname: 'URI:spiffe://rogue.local/services/rogue' });
    expect(run(rogue)).toMatchObject({
      ok: false,
      reason: 'mtls+bad-identity',
      identity: { trustDomain: 'rogue.local', service: 'rogue' },
    });
  });

  it('rejects a legitimate service that is not on this route allowlist', () => {
    const payments = cert({ subjectaltname: 'URI:spiffe://bastion.local/services/payments' });
    expect(run(payments)).toMatchObject({
      reason: 'mtls+bad-identity',
      identity: { service: 'payments' },
    });
  });
});
