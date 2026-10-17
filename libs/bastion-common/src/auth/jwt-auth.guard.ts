import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  ServiceUnavailableException,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AccessRecorder, type AccessContext } from '../audit/access-recorder';
import { describeResource, type ResourceRequest } from '../audit/resource';
import { TRACE_HEADER, resolveTraceId } from '../audit/trace';
import type { PeerRequest } from '../identity/peer-identity.guard';
import type { TokenClaims } from '../jwt/claims';
import { JWT_REASON } from '../jwt/reasons';
import {
  TokenVerifier,
  checkScope,
  extractBearerToken,
  type VerifyResult,
} from '../jwt/verifier';
import type { RandomSource } from '../random/random-source';
import { JWT_VERIFIER, RANDOM } from '../tokens';

export const REQUIRE_SCOPE_KEY = 'bastion:require-scope';

/** Declares the scope a route needs. Every route behind JwtAuthGuard must have one. */
export const RequireScope = (scope: string): ReturnType<typeof SetMetadata> =>
  SetMetadata(REQUIRE_SCOPE_KEY, scope);

/** The request fields this guard reads, and the ones it sets for later handlers. */
export interface AuthRequest extends PeerRequest, ResourceRequest {
  readonly headers?: Readonly<Record<string, string | string[] | undefined>>;
  readonly ip?: string;
  /** Set on every guarded request. Forward it downstream in the `x-bastion-trace-id` header. */
  traceId?: string;
  /** Set once the token verified and the scope check passed. */
  auth?: TokenClaims;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

const NO_TOKEN: Extract<VerifyResult, { ok: false }> = {
  ok: false,
  reason: JWT_REASON.MALFORMED,
};

/**
 * Verifies the bearer token and the route's scope, after PeerIdentityGuard
 * has vouched for the caller. Denials are 401 (bad token), 503 (cannot
 * decide) or 403 (missing scope), and each one is audited and counted.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(JWT_VERIFIER) private readonly verifier: TokenVerifier,
    @Inject(RANDOM) private readonly random: RandomSource,
    @Inject(AccessRecorder) private readonly recorder: AccessRecorder,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthRequest>();
    const required = this.reflector.getAllAndOverride<string | undefined>(REQUIRE_SCOPE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required) throw new ForbiddenException();

    const ctx = this.contextFor(req);
    req.traceId = ctx.traceId;
    const token = extractBearerToken(first(req.headers?.authorization));
    const result = token ? await this.verifier.verify(token) : NO_TOKEN;
    if (!result.ok) {
      this.recorder.jwtDenied(ctx, result);
      const status = isUnavailable(result.reason) ? 503 : 401;
      throw status === 503 ? new ServiceUnavailableException() : new UnauthorizedException();
    }
    const scope = checkScope(result.claims, required);
    if (!scope.ok) {
      this.recorder.scopeDenied(ctx, result.claims, scope.reason);
      throw new ForbiddenException();
    }
    req.auth = result.claims;
    this.recorder.allowed(ctx, result.claims);
    return true;
  }

  private contextFor(req: AuthRequest): AccessContext {
    return {
      resource: describeResource(req),
      traceId: resolveTraceId(req.headers?.[TRACE_HEADER], this.random),
      ...(req.peerIdentity ? { peerIdentity: req.peerIdentity.uri } : {}),
      ...(req.ip ? { remoteAddr: req.ip } : {}),
    };
  }
}

/** A reason that means "we could not decide", so the answer is 503 not 401. */
function isUnavailable(reason: string): boolean {
  return reason === JWT_REASON.JWKS_UNAVAILABLE || reason === JWT_REASON.REPLAY_CACHE_FULL;
}
