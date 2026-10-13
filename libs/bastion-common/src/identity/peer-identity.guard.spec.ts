import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { FakeClock } from '../clock/clock';
import { AllowCallers } from './allow-callers';
import {
  PeerIdentityGuard,
  type PeerDecisionListener,
  type PeerRequest,
} from './peer-identity.guard';
import type { PeerCertLike } from './peer-check';

const NOON = Date.UTC(2026, 9, 12, 12, 0, 0);
const HOUR = 3_600_000;

class Routes {
  @AllowCallers('edge')
  fromEdge(): void {}

  @AllowCallers('orders', 'payments')
  fromTwo(): void {}

  unguarded(): void {}
}

function cert(uri: string): PeerCertLike {
  return {
    subjectaltname: `DNS:x, URI:${uri}`,
    valid_from: 'Oct 12 00:00:00 2026 GMT',
    valid_to: 'Oct 13 00:00:00 2026 GMT',
  };
}

function tlsRequest(c: PeerCertLike, authorized = true): PeerRequest {
  return {
    method: 'POST',
    url: '/orders?x=1',
    socket: { authorized, getPeerCertificate: () => c },
  };
}

function ctx(req: PeerRequest, handler: () => void): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => handler,
    getClass: () => Routes,
  } as unknown as ExecutionContext;
}

function setup(trustDomain = 'bastion.local', withListener = true) {
  const decisions: Parameters<PeerDecisionListener['onPeerDecision']>[0][] = [];
  const listener: PeerDecisionListener = { onPeerDecision: (d) => void decisions.push(d) };
  const clock = new FakeClock(NOON);
  const guard = new PeerIdentityGuard(
    new Reflector(),
    clock,
    { trustDomain },
    withListener ? listener : undefined,
  );
  return { guard, decisions, clock };
}

const EDGE = 'spiffe://bastion.local/services/edge';
const PAYMENTS = 'spiffe://bastion.local/services/payments';
const ROUTES = new Routes();

describe('PeerIdentityGuard', () => {
  it('admits an allowed caller, records its identity and reports the decision', () => {
    const { guard, decisions } = setup();
    const req = tlsRequest(cert(EDGE));
    expect(guard.canActivate(ctx(req, ROUTES.fromEdge))).toBe(true);
    expect(req.peerIdentity?.service).toBe('edge');
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ resource: 'POST /orders', check: { ok: true } });
  });

  it('rejects a caller that is not on the route allowlist', () => {
    const { guard, decisions } = setup();
    expect(() => guard.canActivate(ctx(tlsRequest(cert(PAYMENTS)), ROUTES.fromEdge))).toThrow(
      UnauthorizedException,
    );
    expect(decisions[0]).toMatchObject({ check: { ok: false, reason: 'mtls+bad-identity' } });
  });

  it('honours several allowed callers', () => {
    const { guard } = setup();
    expect(guard.canActivate(ctx(tlsRequest(cert(PAYMENTS)), ROUTES.fromTwo))).toBe(true);
  });

  it('rejects a connection that is not TLS at all', () => {
    const { guard, decisions } = setup();
    const req: PeerRequest = { method: 'GET', url: '/', socket: {} };
    expect(() => guard.canActivate(ctx(req, ROUTES.fromEdge))).toThrow(UnauthorizedException);
    expect(decisions[0]).toMatchObject({ check: { reason: 'mtls+no-client-cert' } });
  });

  it('rejects a TLS socket whose peer was not authorized', () => {
    const { guard, decisions } = setup();
    expect(() => guard.canActivate(ctx(tlsRequest(cert(EDGE), false), ROUTES.fromEdge))).toThrow(
      UnauthorizedException,
    );
    expect(decisions[0]).toMatchObject({ check: { reason: 'mtls+rejected_ca' } });
  });

  it('rejects an expired certificate according to the Clock', () => {
    const { guard, decisions, clock } = setup();
    clock.advanceMs(13 * HOUR);
    expect(() => guard.canActivate(ctx(tlsRequest(cert(EDGE)), ROUTES.fromEdge))).toThrow(
      UnauthorizedException,
    );
    expect(decisions[0]).toMatchObject({ check: { reason: 'mtls+expired' } });
  });

  it('builds allowed IDs from the configured trust domain', () => {
    const { guard } = setup('other.test');
    expect(() => guard.canActivate(ctx(tlsRequest(cert(EDGE)), ROUTES.fromEdge))).toThrow(
      UnauthorizedException,
    );
  });

  it('denies a route that declares no allowlist (fail closed)', () => {
    const { guard, decisions } = setup();
    expect(() => guard.canActivate(ctx(tlsRequest(cert(EDGE)), ROUTES.unguarded))).toThrow(
      ForbiddenException,
    );
    expect(decisions).toHaveLength(0);
  });

  it('works without a listener', () => {
    const { guard } = setup('bastion.local', false);
    expect(guard.canActivate(ctx(tlsRequest(cert(EDGE)), ROUTES.fromEdge))).toBe(true);
  });
});
