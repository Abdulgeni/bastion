import { CompactSign } from 'jose';
import type { Clock } from '../clock/clock';
import type { RandomSource } from '../random/random-source';
import {
  AUDIENCES,
  ISSUER,
  SCOPES,
  TOKEN_TTL_SECONDS,
  isValidSubject,
  type BastionClaims,
  type Scope,
} from './claims';
import { activeKey, type KeyRing, type SigningKey } from './key-ring';

/** Signs `claims` as a compact EdDSA JWS with the key's `kid` in the protected header. */
export async function signClaims(key: SigningKey, claims: BastionClaims): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify(claims));
  return new CompactSign(payload)
    .setProtectedHeader({ alg: 'EdDSA', kid: key.kid, typ: 'JWT' })
    .sign(key.privateKey);
}

export interface IssueRequest {
  readonly sub: string;
  readonly scope: readonly Scope[];
}

export interface IssuedToken {
  readonly token: string;
  readonly claims: BastionClaims;
  readonly kid: string;
}

export interface JwtIssuerDeps {
  /** Called on every issue so a rotated key ring is picked up immediately. */
  readonly ring: () => KeyRing;
  readonly clock: Clock;
  readonly random: RandomSource;
}

/** Mints Bastion's short-lived user tokens. Only edge holds one. */
export class JwtIssuer {
  constructor(private readonly deps: JwtIssuerDeps) {}

  /** Issues a 5-minute token for `sub` addressed to every service, with a random single-use `jti`. */
  async issue(req: IssueRequest): Promise<IssuedToken> {
    if (!isValidSubject(req.sub)) throw new RangeError('invalid subject');
    const unknown = req.scope.filter((s) => !(SCOPES as readonly string[]).includes(s));
    if (unknown.length > 0 || req.scope.length === 0) throw new RangeError('invalid scope');
    const key = activeKey(this.deps.ring());
    const iat = this.deps.clock.nowSec();
    const claims: BastionClaims = {
      iss: ISSUER,
      sub: req.sub,
      aud: [...AUDIENCES],
      iat,
      exp: iat + TOKEN_TTL_SECONDS,
      jti: this.deps.random.bytes(16).toString('hex'),
      scope: [...req.scope],
    };
    return { token: await signClaims(key, claims), claims, kid: key.kid };
  }
}
