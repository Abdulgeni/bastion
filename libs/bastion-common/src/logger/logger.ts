import pino, { type DestinationStream, type Logger } from 'pino';
import type { Clock } from '../clock/clock';
import type { ServiceName } from '../config/config';

/** Fields that must never reach a log line (tokens, keys, certs). */
export const REDACT_PATHS: readonly string[] = [
  'authorization',
  '*.authorization',
  '**.authorization',
  'headers.authorization',
  'req.headers.authorization',
  'token',
  '*.token',
  '**.token',
  'jwt',
  '*.jwt',
  '**.jwt',
  'password',
  '*.password',
  '**.password',
  'secret',
  '*.secret',
  '**.secret',
  'key',
  '*.key',
  '**.key',
  'apiKey',
  '*.apiKey',
  '**.apiKey',
  'api_key',
  '*.api_key',
  '**.api_key',
  'privateKey',
  '*.privateKey',
  '**.privateKey',
  'cert',
  '*.cert',
  '**.cert',
  'pem',
  '*.pem',
  '**.pem',
];

export interface LoggerOptions {
  readonly service: ServiceName;
  readonly level: string;
  /** Timestamps come from here so tests control them. */
  readonly clock: Clock;
  /** Defaults to stdout. */
  readonly destination?: DestinationStream;
}

/** JSON logger: `{ts, level, service, msg, ...}` with sensitive fields redacted. */
export function createLogger(opts: LoggerOptions): Logger {
  return pino(
    {
      level: opts.level,
      base: { service: opts.service },
      timestamp: () => `,"ts":"${opts.clock.now().toISOString()}"`,
      formatters: { level: (label) => ({ level: label }) },
      redact: { paths: [...REDACT_PATHS], censor: '[REDACTED]' },
    },
    opts.destination ?? pino.destination(1),
  );
}
