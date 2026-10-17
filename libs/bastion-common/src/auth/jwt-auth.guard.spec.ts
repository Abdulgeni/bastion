import {
  ForbiddenException,
  ServiceUnavailableException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { FakeClock } from '../clock/clock';
import { SeededRandom } from '../random/random-source';
import { JwtKeyStore } from '../jwt/key-store';
import { TokenIssuer } from '../jwt/issuer';
import { JwksCache } from '../jwt/jwks-cache';
import { TokenVerifier } from '../jwt/verifier';
import { ReplayCache } from '../jwt/replay-cache';
import { buildJwks } from '../jwt/jwks';
import { AuditService, type AuditSink } from '../audit/audit.service';
import { AccessRecorder } from '../audit/access-recorder';
import { MetricsService, METRIC_NAMES } from '../metrics/metrics.service';
import { TRACE_HEADER } from '../audit/trace';
import { JwtAuthGuard, RequireScope, type AuthRequest } from './jwt-auth.guard';
import { generateSigningKeyPem } from '../jwt/key-store';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

class Routes {
  @RequireScope('orders:write')
  create(): void {}

  @RequireScope('payments:charge')
  pay(): void {}

  unscoped(): void {}
}
const ROUTES = new Routes();
const EDGE = {
  uri: 'spiffe://bastion.local/services/edge',
  trustDomain: 'bastion.local',
  service: 'edge',
};

function ctx(req: AuthRequest, handler: () => void): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => handler,
    getClass: () => Routes,
  } as unknown as ExecutionContext;
}

function request(authorization?: string, extra: Partial<AuthRequest> = {}): AuthRequest {
  return {
    method: 'POST',
    url: '/orders?x=1',
    route: { path: '/orders' },
    ip: '10.0.0.5',
    peerIdentity: EDGE as never,
    headers: authorization ? { authorization } : {},
    ...extra,
  };
}

/** A tiny key-store-backed world; the JWKS resolver reads from the same store. */
async function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'bastion-guard-'));
  mkdirSync(join(dir, 'jwt'), { recursive: true });
  const random = new SeededRandom('guard');
  const { kid, pem } = generateSigningKeyPem(random);
  writeFileSync(join(dir, 'jwt', `${kid}.pem`), pem, { mode: 0o600 });
  writeFileSync(join(dir, 'jwt', 'current'), `${kid}\n`, { mode: 0o600 });
  const store = await JwtKeyStore.load(dir);
  const clock = new FakeClock(Date.UTC(2026, 9, 12, 12, 0, 0));
  const issuer = new TokenIssuer(store, clock, new SeededRandom('issuer'), 'edge');
  const state = { down: false };
  const jwks = new JwksCache({
    url: 'http://edge/jwks',
    clock,
    http: {
      getJson: async () => {
        if (state.down) throw new Error('down');
        return buildJwks(store);
      },
    },
  });
  const replay = new ReplayCache(clock);
  const verifier = new TokenVerifier({
    serviceName: 'orders',
    expectedAudience: 'orders',
    expectedIssuer: 'edge',
    clock,
    jwks,
    replay,
  });
  const lines: string[] = [];
  const sink: AuditSink = { write: (l) => lines.push(l) };
  const audit = new AuditService({ service: 'orders', clock, sinks: [sink] });
  const metrics = new MetricsService('orders', clock);
  const recorder = new AccessRecorder(audit, metrics);
  const guard = new JwtAuthGuard(new Reflector(), verifier, random, recorder);
  const bearer = async (over: { sub?: string; scope?: string[] } = {}) => {
    const issued = await issuer.issue({
      subject: over.sub ?? 'alice',
      audience: ['orders'],
      scope: over.scope ?? ['orders:write'],
    });
    return { header: `Bearer ${issued.token}`, token: issued.token };
  };
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
  return { guard, clock, state, bearer, events, sample };
}

describe('JwtAuthGuard: allowed', () => {
  it('admits a valid token, exposes the claims and trace ID, and audits one allow line', async () => {
    const { guard, bearer, events, sample } = await setup();
    const { header } = await bearer();
    const req = request(header);
    expect(await guard.canActivate(ctx(req, ROUTES.create))).toBe(true);
    expect(req.auth?.sub).toBe('alice');
    expect(req.traceId).toMatch(/^[0-9a-f]{16}$/);
    expect(events()).toHaveLength(1);
    expect(events()[0]).toMatchObject({
      event: 'access',
      decision: 'allow',
      reason: 'ok',
      resource: 'POST /orders',
      user_sub: 'alice',
      peer_identity: EDGE.uri,
      remote_addr: '10.0.0.5',
      trace_id: req.traceId,
    });
    expect(await sample(METRIC_NAMES.AUTHZ, { decision: 'allow', resource: 'POST /orders' })).toBe(1);
  });

  it('keeps a valid incoming trace ID and replaces a bad one', async () => {
    const { guard, bearer } = await setup();
    const a = await bearer();
    const kept = request(undefined, {
      headers: { authorization: a.header, [TRACE_HEADER]: '0123456789abcdef' },
    });
    await guard.canActivate(ctx(kept, ROUTES.create));
    expect(kept.traceId).toBe('0123456789abcdef');
    const b = await bearer();
    const bad = request(undefined, {
      headers: { authorization: b.header, [TRACE_HEADER]: 'nope' },
    });
    await guard.canActivate(ctx(bad, ROUTES.create));
    expect(bad.traceId).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('JwtAuthGuard: denied', () => {
  it.each([[undefined], ['Bearer'], ['Basic abc.def.ghi'], ['Bearer not-a-jwt']])(
    'answers 401 jwt+malformed for the header %p',
    async (header) => {
      const { guard, events } = await setup();
      await expect(
        guard.canActivate(ctx(request(header), ROUTES.create)),
      ).rejects.toThrow(UnauthorizedException);
      expect(events()[0]).toMatchObject({ decision: 'deny', reason: 'jwt+malformed', status: 401 });
    },
  );

  it('answers 401 jwt+replayed on the second use and names the user', async () => {
    const { guard, bearer, events, sample } = await setup();
    const { header } = await bearer();
    await guard.canActivate(ctx(request(header), ROUTES.create));
    await expect(guard.canActivate(ctx(request(header), ROUTES.create))).rejects.toThrow(
      UnauthorizedException,
    );
    expect(events()[1]).toMatchObject({ reason: 'jwt+replayed', status: 401 });
    expect(await sample(METRIC_NAMES.JWT, { outcome: 'replayed' })).toBe(1);
  });

  it('answers 401 jwt+expired once the token has lived 5 minutes', async () => {
    const { guard, clock, bearer, events } = await setup();
    const { header } = await bearer();
    clock.advanceMs(300_000);
    await expect(guard.canActivate(ctx(request(header), ROUTES.create))).rejects.toThrow(
      UnauthorizedException,
    );
    expect(events()[0]).toMatchObject({ reason: 'jwt+expired' });
  });

  it('answers 503 jwks+unavailable when edge cannot be reached', async () => {
    const { guard, state, bearer, events } = await setup();
    const { header } = await bearer();
    state.down = true;
    await expect(guard.canActivate(ctx(request(header), ROUTES.create))).rejects.toThrow(
      ServiceUnavailableException,
    );
    expect(events()[0]).toMatchObject({ reason: 'jwks+unavailable', status: 503 });
  });

  it('answers 403 when the token lacks the scope this route needs', async () => {
    const { guard, bearer, events } = await setup();
    const { header } = await bearer({ scope: ['orders:write'] });
    await expect(guard.canActivate(ctx(request(header), ROUTES.pay))).rejects.toThrow(
      ForbiddenException,
    );
    expect(events()[0]).toMatchObject({
      decision: 'deny',
      reason: 'scope+missing:payments:charge',
      status: 403,
      user_sub: 'alice',
    });
  });

  it('denies a route that declares no scope, without auditing it as a token problem', async () => {
    const { guard, bearer, events } = await setup();
    const { header } = await bearer();
    await expect(guard.canActivate(ctx(request(header), ROUTES.unscoped))).rejects.toThrow(
      ForbiddenException,
    );
    expect(events()).toHaveLength(0);
  });
});
