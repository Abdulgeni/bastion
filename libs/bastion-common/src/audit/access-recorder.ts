import { Inject, Injectable } from '@nestjs/common';
import type { TokenClaims } from '../jwt/claims';
import type { VerifyResult } from '../jwt/verifier';
import type { PeerCheck } from '../identity/peer-check';
import type { PeerDecisionListener } from '../identity/peer-identity.guard';
import { MetricsService } from '../metrics/metrics.service';
import { MTLS_OUTCOME_BY_REASON, MTLS_REASON } from '../mtls/reasons';
import type { TlsRejection } from '../mtls/tls-errors';
import { AuditService } from './audit.service';

/** Who is asking for what, as known to the guard that is deciding. */
export interface AccessContext {
  readonly resource: string;
  readonly traceId: string;
  readonly peerIdentity?: string;
  readonly remoteAddr?: string;
}

type DeniedJwt = Extract<VerifyResult, { ok: false }>;

/** Turns every security decision into one audit event plus the matching metrics. */
@Injectable()
export class AccessRecorder implements PeerDecisionListener {
  constructor(
    @Inject(AuditService) private readonly audit: AuditService,
    @Inject(MetricsService) private readonly metrics: MetricsService,
  ) {}

  /** PeerIdentityGuard seam: counts every identity check, audits the denials. */
  onPeerDecision(decision: { readonly resource: string; readonly check: PeerCheck }): void {
    const { resource, check } = decision;
    const reason = check.ok ? MTLS_REASON.OK : check.reason;
    this.metrics.recordHandshake(MTLS_OUTCOME_BY_REASON[reason]);
    if (check.ok) return;
    this.metrics.recordAuthz('deny', resource);
    this.audit.record({
      event: 'access',
      decision: 'deny',
      reason,
      resource,
      status: 401,
      ...(check.identity ? { peer_identity: check.identity.uri } : {}),
    });
  }

  /** A handshake Node aborted before any request existed. */
  onTlsRejection(rejection: TlsRejection): void {
    this.metrics.recordHandshake(rejection.outcome);
    this.audit.record({
      event: 'handshake',
      decision: 'deny',
      reason: rejection.reason,
      detail: rejection.detail,
      ...(rejection.remoteAddress ? { remote_addr: rejection.remoteAddress } : {}),
    });
  }

  /** The token was rejected (401) or could not be judged (503). */
  jwtDenied(ctx: AccessContext, result: DeniedJwt): void {
    const outcome = result.reason === 'jwt+ok' ? undefined : undefined;
    void outcome;
    this.metrics.recordAuthz('deny', ctx.resource);
    this.audit.record({
      ...this.base(ctx),
      decision: 'deny',
      reason: result.reason,
      status: result.reason === 'jwks+unavailable' || result.reason === 'replay+cache_full' ? 503 : 401,
      ...this.subject(result.ok === false && 'claims' in result ? undefined : undefined),
    });
  }

  /** The token was valid but lacks the scope this route needs (403). */
  scopeDenied(ctx: AccessContext, claims: TokenClaims, reason: string): void {
    this.metrics.recordJwt('ok');
    this.metrics.recordAuthz('deny', ctx.resource);
    this.audit.record({
      ...this.base(ctx),
      decision: 'deny',
      reason,
      status: 403,
      ...this.subject(claims),
    });
  }

  /** Every check passed. */
  allowed(ctx: AccessContext, claims: TokenClaims): void {
    this.metrics.recordJwt('ok');
    this.metrics.recordAuthz('allow', ctx.resource);
    this.audit.record({ ...this.base(ctx), decision: 'allow', reason: 'ok', ...this.subject(claims) });
  }

  private base(ctx: AccessContext) {
    return {
      event: 'access' as const,
      resource: ctx.resource,
      trace_id: ctx.traceId,
      ...(ctx.peerIdentity ? { peer_identity: ctx.peerIdentity } : {}),
      ...(ctx.remoteAddr ? { remote_addr: ctx.remoteAddr } : {}),
    };
  }

  private subject(claims: TokenClaims | undefined) {
    return claims ? { user_sub: claims.sub, jwt_jti: claims.jti } : {};
  }
}
