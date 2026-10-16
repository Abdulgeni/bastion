/** Issuer name carried in every Bastion token (`iss`). */
export const ISSUER = 'bastion-edge';

/** Token lifetime in seconds (5 minutes). Replay tracking relies on this upper bound. */
export const TOKEN_TTL_SECONDS = 300;

/** Services a token is addressed to. Each service accepts it only if its own name is listed. */
export const AUDIENCES = ['orders', 'inventory', 'payments'] as const;
export type Audience = (typeof AUDIENCES)[number];

/** Per-endpoint scopes. */
export const SCOPES = ['orders:write', 'inventory:reserve', 'payments:charge'] as const;
export type Scope = (typeof SCOPES)[number];

/** The claims Bastion reads from a verified token. Anything else in the payload is ignored. */
export interface BastionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: readonly string[];
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
  readonly scope: readonly string[];
}

const SUBJECT = /^[A-Za-z0-9._@-]{1,64}$/;
const JTI = /^[0-9a-f]{32}$/;
const NAME = /^[a-z][a-z0-9:-]{0,63}$/;
const MAX_LIST = 16;

/** True for a username-like subject: 1 to 64 characters of [A-Za-z0-9._@-]. */
export function isValidSubject(value: unknown): value is string {
  return typeof value === 'string' && SUBJECT.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nameList(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LIST) return undefined;
  const ok = value.every((v) => typeof v === 'string' && NAME.test(v));
  return ok ? (value as string[]) : undefined;
}

function seconds(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/**
 * Validates an untrusted JWT payload. Returns the claims Bastion uses, or undefined if
 * anything is missing or malformed. Never throws, whatever it is given.
 */
export function parseClaims(payload: unknown): BastionClaims | undefined {
  if (!isRecord(payload)) return undefined;
  const { iss, sub, jti } = payload;
  const aud = nameList(payload.aud);
  const scope = nameList(payload.scope);
  const iat = seconds(payload.iat);
  const exp = seconds(payload.exp);
  if (typeof iss !== 'string' || !isValidSubject(sub)) return undefined;
  if (typeof jti !== 'string' || !JTI.test(jti)) return undefined;
  if (!aud || !scope || iat === undefined || exp === undefined) return undefined;
  return { iss, sub, aud, iat, exp, jti, scope };
}
