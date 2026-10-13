import { readFileSync } from 'node:fs';
import type { TlsFiles } from '../config/config';
import { ConfigError } from '../errors';

/** PEM bytes a service needs for TLS: its own cert and key, and the CA it trusts. */
export interface TlsMaterial {
  readonly cert: Buffer;
  readonly key: Buffer;
  readonly ca: Buffer;
}

function readRequired(label: string, path: string, issues: string[]): Buffer {
  try {
    const data = readFileSync(path);
    if (data.length === 0) issues.push(`${label}: file is empty (${path})`);
    return data;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'UNKNOWN';
    issues.push(`${label}: cannot read ${path} (${code})`);
    return Buffer.alloc(0);
  }
}

/** Reads cert, key and CA PEM files. Throws ConfigError listing every missing or empty file. */
export function readTlsMaterial(files: TlsFiles): TlsMaterial {
  const issues: string[] = [];
  const cert = readRequired('TLS_CERT_FILE', files.certFile, issues);
  const key = readRequired('TLS_KEY_FILE', files.keyFile, issues);
  const ca = readRequired('TLS_CA_FILE', files.caFile, issues);
  if (issues.length > 0) throw new ConfigError(issues);
  return { cert, key, ca };
}
