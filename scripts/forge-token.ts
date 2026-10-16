import type { Clock } from '../libs/bastion-common/src/clock/clock';
import {
  ISSUER,
  TOKEN_TTL_SECONDS,
  type BastionClaims,
} from '../libs/bastion-common/src/jwt/claims';
import { signClaims } from '../libs/bastion-common/src/jwt/issuer';
import { activeKey, defaultKeyRingPath, readKeyRingFile, type KeyRing } from '../libs/bastion-common/src/jwt/key-ring';
import type { RandomSource } from '../libs/bastion-common/src/random/random-source';
import { readCliOptions, runCli } from './pki/cli-options';

/** TEST/DEMO ONLY. Needs edge's private signing key, which no service container has. */
export interface ForgeOptions {
  readonly ring: KeyRing;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly aud: readonly string[];
  readonly sub?: string;
  readonly scope?: readonly string[];
}

export async function forgeToken(opts: ForgeOptions): Promise<string> {
  const iat = opts.clock.nowSec();
  const claims: BastionClaims = {
    iss: ISSUER,
    sub: opts.sub ?? 'alice',
    aud: [...opts.aud],
    iat,
    exp: iat + TOKEN_TTL_SECONDS,
    jti: opts.random.bytes(16).toString('hex'),
    scope: [...(opts.scope ?? ['orders:write', 'inventory:reserve', 'payments:charge'])],
  };
  return signClaims(activeKey(opts.ring), claims);
}

export function tamperPayload(token: string, patch: Readonly<Record<string, unknown>>): string {
  const [header, payload, signature] = token.split('.');
  if (header === undefined || payload === undefined || signature === undefined) {
    throw new Error('not a compact JWS');
  }
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
  const edited = Buffer.from(JSON.stringify({ ...claims, ...patch })).toString('base64url');
  return `${header}.${edited}.${signature}`;
}

function flag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

const USAGE = 'usage: forge-token forge --aud a,b [--sub s] [--scope x,y] | tamper --token T --aud a,b';

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const opts = readCliOptions(process.env, argv);
  const aud = flag(argv, 'aud')?.split(',');
  if (!aud) throw new Error(USAGE);
  if (argv[0] === 'tamper') {
    const token = flag(argv, 'token');
    if (!token) throw new Error(USAGE);
    process.stdout.write(`${tamperPayload(token, { aud })}\n`);
    return;
  }
  if (argv[0] !== 'forge') throw new Error(USAGE);
  const ring = readKeyRingFile(defaultKeyRingPath(opts.varDir));
  const scope = flag(argv, 'scope')?.split(',');
  process.stdout.write(`${await forgeToken({ ring, clock: opts.clock, random: opts.random, aud, sub: flag(argv, 'sub'), scope })}\n`);
}

if (require.main === module) runCli(main);
