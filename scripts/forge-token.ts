import { TokenIssuer } from '../libs/bastion-common/src/jwt/issuer';
import { JwtKeyStore } from '../libs/bastion-common/src/jwt/key-store';
import { readCliOptions, runCli } from './pki/cli-options';

function flag(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

/** Splits a compact JWS and rejects anything that is not three dot-separated parts. */
function parts(token: string): [string, string, string] {
  const split = token.split('.');
  if (split.length !== 3 || split[0] === undefined || split[1] === undefined || split[2] === undefined) {
    throw new Error('not a compact JWS');
  }
  return [split[0], split[1], split[2]];
}

/**
 * Edits fields in a token's payload while keeping its original header and
 * signature. The result no longer verifies: this is what a naive attacker's
 * edit looks like. Used by `demo-stolen-jwt` to show `jwt+bad_sig`.
 */
export function tamperPayload(token: string, patch: Readonly<Record<string, unknown>>): string {
  const [header, payload, signature] = parts(token);
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
  const edited = Buffer.from(JSON.stringify({ ...claims, ...patch })).toString('base64url');
  return `${header}.${edited}.${signature}`;
}

const USAGE =
  'usage: forge-token forge --aud a,b [--sub s] [--scope x,y] | tamper --token T --aud a,b';

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const opts = readCliOptions(process.env, argv);
  const aud = flag(argv, 'aud')?.split(',');
  if (!aud || aud.length === 0) throw new Error(USAGE);

  if (argv[0] === 'tamper') {
    const token = flag(argv, 'token');
    if (!token) throw new Error(USAGE);
    process.stdout.write(`${tamperPayload(token, { aud })}\n`);
    return;
  }

  if (argv[0] !== 'forge') throw new Error(USAGE);

  const store = await JwtKeyStore.load(opts.varDir);
  const issuer = new TokenIssuer(store, opts.clock, opts.random, 'edge');
  const scope = flag(argv, 'scope')?.split(',') ?? ['orders:write'];
  const subject = flag(argv, 'sub') ?? 'alice';
  const issued = await issuer.issue({ subject, audience: aud, scope });
  process.stdout.write(`${issued.token}\n`);
}

if (require.main === module) runCli(main);
