import { SystemClock, type Clock } from '../../libs/bastion-common/src/clock/clock';
import { ConfigError } from '../../libs/bastion-common/src/errors';
import {
  createRandomSource,
  type RandomSource,
} from '../../libs/bastion-common/src/random/random-source';

/** Everything the PKI scripts need, whether called from the CLI or from tests. */
export interface PkiOptions {
  readonly varDir: string;
  readonly trustDomain: string;
  readonly random: RandomSource;
  readonly clock: Clock;
  readonly certTtlHours: number;
  readonly caTtlDays: number;
  /** A service cert with less than this much validity left is re-issued by gen-certs. */
  readonly renewWindowMs: number;
}

export interface CliOptions extends PkiOptions {
  readonly forceCa: boolean;
}

type Env = Readonly<Record<string, string | undefined>>;

function positiveInt(name: string, raw: string | undefined, fallback: number, issues: string[]): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    issues.push(`${name} must be a positive integer`);
    return fallback;
  }
  return n;
}

/**
 * Reads CLI options from the environment and argv. Randomness is the OS CSPRNG unless
 * BASTION_TEST_SEED is set, which is refused when NODE_ENV=production.
 */
export function readCliOptions(env: Env, argv: readonly string[]): CliOptions {
  const issues: string[] = [];
  const certTtlHours = positiveInt('BASTION_CERT_TTL_HOURS', env.BASTION_CERT_TTL_HOURS, 168, issues);
  const caTtlDays = positiveInt('BASTION_CA_TTL_DAYS', env.BASTION_CA_TTL_DAYS, 365, issues);
  if (issues.length > 0) throw new ConfigError(issues);
  return {
    varDir: env.BASTION_VAR_DIR ?? './var',
    trustDomain: env.BASTION_TRUST_DOMAIN ?? 'bastion.local',
    random: createRandomSource({ nodeEnv: env.NODE_ENV, seed: env.BASTION_TEST_SEED }),
    clock: new SystemClock(),
    certTtlHours,
    caTtlDays,
    renewWindowMs: 3_600_000,
    forceCa: argv.includes('--force-ca'),
  };
}

/** Runs a CLI main(), printing only the error message (never a stack) and exiting 1 on failure. */
export function runCli(main: () => Promise<void>): void {
  main().catch((err: unknown) => {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
