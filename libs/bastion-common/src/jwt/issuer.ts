import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import type { Clock } from '../clock/clock';
import type { RandomSource } from '../random/random-source';
import type { JwtKeyStore } from './key-store';

export interface IssueOptions {
  readonly subject: string;
  readonly audience: readonly string[];
  readonly scope: readonly string[];
  readonly issuer?: string;
  /** Token lifetime in seconds. Defaults to 300 (5 minutes). */
  readonly ttlSeconds?: number;
  /** Clock skew in seconds, subtracted from `iat`. Defaults to 5. */
  readonly skewSeconds?: number;
}

export interface IssuedToken {
  readonly token: string;
  readonly claims: {
    readonly sub: string;
    readonly aud: readonly string[];
    readonly iss: string;
    readonly iat: number;
    readonly exp: number;
    readonly jti: string;
    readonly scope: readonly string[];
  };
}

const DEFAULT_TTL_SECONDS = 300;
const DEFAULT_SKEW_SECONDS = 5;

/**
 * Mints short-lived JWT user tokens. The `jti` mixes in bytes from the
 * injected RandomSource so tests get deterministic tokens and the CSPRNG is
 * the only source in production.
 */
export class TokenIssuer {
  constructor(
    private readonly keyStore: JwtKeyStore,
    private readonly clock: Clock,
    private readonly random: RandomSource,
    private readonly defaultIssuer = 'edge',
  ) {}

  async issue(options: IssueOptions): Promise<IssuedToken> {
    const signing = this.keyStore.current();
    const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const skew = options.skewSeconds ?? DEFAULT_SKEW_SECONDS;
    const iat = this.clock.nowSec() - skew;
    const exp = iat + ttl + skew;
    const jti = this.newJti();
    const iss = options.issuer ?? this.defaultIssuer;

    const token = await new SignJWT({
      sub: options.subject,
      aud: [...options.audience],
      scope: [...options.scope],
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: signing.kid })
      .setIssuer(iss)
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .setJti(jti)
      .sign(signing.key);

    return {
      token,
      claims: {
        sub: options.subject,
        aud: [...options.audience],
        iss,
        iat,
        exp,
        jti,
        scope: [...options.scope],
      },
    };
  }

  private newJti(): string {
    const mix = this.random.bytes(16).toString('hex');
    return `${randomUUID()}-${mix.slice(0, 8)}`;
  }
}
