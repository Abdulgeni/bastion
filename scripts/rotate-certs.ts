#!/usr/bin/env node
/**
 * Re-issue per-service leaf certificates, leaving the CA untouched.
 *
 * Usage:
 *   ts-node scripts/rotate-certs.ts [--seed HEX] [--now ISO8601]
 *
 * Runs `gen-certs.ts --force` against the existing CA. If the CA is missing
 * this exits nonzero; run `gen-certs.ts` first.
 */
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join, resolve } from 'node:path';

const here = __dirname;
const genScript = resolve(here, 'gen-certs.ts');

function main(): void {
  const caPath = join(process.env.BASTION_VAR_DIR ?? 'var', 'ca', 'ca.pem');
  if (!existsSync(caPath)) {
    process.stderr.write(`no CA at ${caPath}; run gen-certs.ts first\n`);
    process.exit(1);
  }
  const args = ['ts-node', genScript, '--force', ...process.argv.slice(2)];
  const child = spawn('pnpm', args, { stdio: 'inherit', shell: process.platform === 'win32' });
  child.on('exit', (code) => process.exit(code ?? 1));
}

main();
