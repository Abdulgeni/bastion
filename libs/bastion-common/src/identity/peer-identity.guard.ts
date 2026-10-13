import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Clock } from '../clock/clock';
import type { BastionConfig, ServiceName } from '../config/config';
import { MTLS_REASON } from '../mtls/reasons';
import { BASTION_CONFIG, CLOCK } from '../tokens';
import { ALLOW_CALLERS_KEY } from './allow-callers';
import { checkPeer, type PeerCertLike, type PeerCheck } from './peer-check';
import { spiffeIdFor, type SpiffeId } from './spiffe';

/** Receives every identity decision (Step 8 plugs audit + metrics in here). */
export interface PeerDecisionListener {
  onPeerDecision(decision: { readonly resource: string; readonly check: PeerCheck }): void;
}

export const PEER_DECISION_LISTENER = Symbol('BASTION_PEER_DECISION_LISTENER');

interface TlsSocketLike {
  readonly authorized?: boolean;
  getPeerCertificate?: () => PeerCertLike;
}

/** The slice of the HTTP request this guard touches; `peerIdentity` is set on success. */
export interface PeerRequest {
  readonly socket?: TlsSocketLike;
  readonly method?: string;
  readonly url?: string;
  readonly route?: { readonly path?: unknown };
  peerIdentity?: SpiffeId;
}

function describeResource(req: PeerRequest): string {
  const path = typeof req.route?.path === 'string' ? req.route.path : (req.url ?? '').split('?')[0];
  return `${req.method ?? 'UNKNOWN'} ${path}`.slice(0, 200);
}

/**
 * Post-handshake workload-identity check. Every guarded route must declare
 * `@AllowCallers(...)`; a route without one is denied (fail closed).
 */
@Injectable()
export class PeerIdentityGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(BASTION_CONFIG) private readonly config: Pick<BastionConfig, 'trustDomain'>,
    @Optional() @Inject(PEER_DECISION_LISTENER) private readonly listener?: PeerDecisionListener,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<PeerRequest>();
    const services = this.reflector.getAllAndOverride<readonly ServiceName[] | undefined>(
      ALLOW_CALLERS_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!services || services.length === 0) throw new ForbiddenException();

    const allowedIds = services.map((s) => spiffeIdFor(this.config.trustDomain, s));
    const check = this.evaluate(req, allowedIds);
    this.listener?.onPeerDecision({ resource: describeResource(req), check });
    if (!check.ok) throw new UnauthorizedException();
    req.peerIdentity = check.identity;
    return true;
  }

  private evaluate(req: PeerRequest, allowedIds: readonly string[]): PeerCheck {
    const socket = req.socket;
    if (typeof socket?.getPeerCertificate !== 'function') {
      return { ok: false, reason: MTLS_REASON.NO_CLIENT_CERT };
    }
    if (socket.authorized !== true) return { ok: false, reason: MTLS_REASON.REJECTED_CA };
    return checkPeer({ cert: socket.getPeerCertificate(), clock: this.clock, allowedIds });
  }
}
