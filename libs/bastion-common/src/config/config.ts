import 'reflect-metadata';
import { join } from 'node:path';
import { plainToInstance, Type } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsIP,
  IsOptional,
  IsString,
  Matches,
  Max,
  Min,
  MinLength,
  validateSync,
} from 'class-validator';
import { assertSeedAllowed } from '../random/random-source';
import { ConfigError } from '../errors';

export const SERVICE_NAMES = ['edge', 'orders', 'inventory', 'payments'] as const;
export type ServiceName = (typeof SERVICE_NAMES)[number];

const NODE_ENVS = ['development', 'test', 'production'] as const;
const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;

/** Default listener ports per service (overridable with DATA_PORT / MGMT_PORT). */
export const PORT_DEFAULTS: Readonly<Record<ServiceName, { data: number; mgmt: number }>> = {
  edge: { data: 8080, mgmt: 9090 },
  orders: { data: 8443, mgmt: 9091 },
  inventory: { data: 8444, mgmt: 9092 },
  payments: { data: 8445, mgmt: 9093 },
};

export interface ListenerConfig {
  readonly host: string;
  readonly port: number;
}

export interface TlsFiles {
  readonly certFile: string;
  readonly keyFile: string;
  readonly caFile: string;
}

/** Where the JWT verifier caches edge's public key set. */
export interface JwtConfig {
  /** URL of the JWKS document. Defaults to edge's management port. */
  readonly jwksUrl: string;
  /** Hard cap on the per-service replay cache. */
  readonly replayCacheSize: number;
  /** Directory holding the edge-only JWT signing keys (`<kid>.pem` + `current`). */
  readonly keyStoreDir: string;
}

export interface BastionConfig {
  readonly serviceName: ServiceName;
  readonly nodeEnv: (typeof NODE_ENVS)[number];
  readonly trustDomain: string;
  readonly logLevel: (typeof LOG_LEVELS)[number];
  readonly data: ListenerConfig;
  readonly mgmt: ListenerConfig;
  readonly tls: TlsFiles;
  readonly auditDir: string;
  readonly jwt: JwtConfig;
  /** True when this process is edge (JWT issuer + JWKS publisher). */
  readonly isEdge: boolean;
  /** Test-only; never set in production (enforced at load). */
  readonly testSeed?: string;
}

class EnvSchema {
  @IsIn(SERVICE_NAMES) SERVICE_NAME!: ServiceName;
  @IsIn(NODE_ENVS) NODE_ENV!: (typeof NODE_ENVS)[number];
  @IsIP() DATA_BIND_ADDR!: string;
  @IsIP() MGMT_BIND_ADDR!: string;

  @IsOptional() @IsIn(LOG_LEVELS) LOG_LEVEL?: (typeof LOG_LEVELS)[number];
  @IsOptional() @Matches(/^[a-z0-9]+([.-][a-z0-9]+)*$/) BASTION_TRUST_DOMAIN?: string;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(65535) DATA_PORT?: number;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(65535) MGMT_PORT?: number;
  @IsOptional() @IsString() @MinLength(1) BASTION_VAR_DIR?: string;
  @IsOptional() @IsString() @MinLength(1) TLS_CERT_FILE?: string;
  @IsOptional() @IsString() @MinLength(1) TLS_KEY_FILE?: string;
  @IsOptional() @IsString() @MinLength(1) TLS_CA_FILE?: string;
  @IsOptional() @IsString() @MinLength(1) AUDIT_DIR?: string;
  @IsOptional() @IsString() @MinLength(1) BASTION_TEST_SEED?: string;
  @IsOptional() @IsString() @MinLength(1) JWKS_URL?: string;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) REPLAY_CACHE_SIZE?: number;
  @IsOptional() @IsString() @MinLength(1) JWT_KEYS_DIR?: string;
}

function parseEnv(env: Readonly<Record<string, string | undefined>>): EnvSchema {
  const parsed = plainToInstance(EnvSchema, env);
  const errors = validateSync(parsed);
  if (errors.length > 0) {
    const issues = errors.flatMap((e) => Object.values(e.constraints ?? {}));
    throw new ConfigError(issues);
  }
  return parsed;
}

function buildConfig(e: EnvSchema): BastionConfig {
  const service = e.SERVICE_NAME;
  const varDir = e.BASTION_VAR_DIR ?? './var';
  const ports = PORT_DEFAULTS[service];
  const mgmtPort = e.MGMT_PORT ?? ports.mgmt;
  return {
    serviceName: service,
    nodeEnv: e.NODE_ENV,
    trustDomain: e.BASTION_TRUST_DOMAIN ?? 'bastion.local',
    logLevel: e.LOG_LEVEL ?? 'info',
    data: { host: e.DATA_BIND_ADDR, port: e.DATA_PORT ?? ports.data },
    mgmt: { host: e.MGMT_BIND_ADDR, port: mgmtPort },
    tls: {
      certFile: e.TLS_CERT_FILE ?? join(varDir, 'certs', service, 'cert.pem'),
      keyFile: e.TLS_KEY_FILE ?? join(varDir, 'certs', service, 'key.pem'),
      caFile: e.TLS_CA_FILE ?? join(varDir, 'ca', 'ca.pem'),
    },
    auditDir: e.AUDIT_DIR ?? join(varDir, 'audit'),
    jwt: {
      jwksUrl: e.JWKS_URL ?? `http://edge:${mgmtPort}/.well-known/jwks.json`,
      replayCacheSize: e.REPLAY_CACHE_SIZE ?? 100_000,
      keyStoreDir: e.JWT_KEYS_DIR ?? join(varDir, 'jwt'),
    },
    isEdge: service === 'edge',
    testSeed: e.BASTION_TEST_SEED,
  };
}

/**
 * Validates the environment and returns typed config. Throws ConfigError (never
 * echoing values) on any problem. Bind addresses and NODE_ENV are required: no
 * silent fallbacks.
 */
export function loadConfig(
  env: Readonly<Record<string, string | undefined>> = process.env,
): BastionConfig {
  const parsed = parseEnv(env);
  assertSeedAllowed(parsed.NODE_ENV, parsed.BASTION_TEST_SEED);
  return buildConfig(parsed);
}
