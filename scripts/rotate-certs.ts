import { SERVICE_NAMES, type ServiceName } from '../libs/bastion-common/src/config/config';
import { issueService } from './gen-certs';
import { readCliOptions, runCli, type PkiOptions } from './pki/cli-options';
import { pkiPaths, readCaSigner } from './pki/layout';

/**
 * Re-issues every service certificate with a fresh key, signed by the existing CA.
 * The CA files are only read, never written. Services pick the new files up on restart.
 */
export async function rotateServiceCerts(opts: PkiOptions): Promise<readonly ServiceName[]> {
  const paths = pkiPaths(opts.varDir);
  const ca = await readCaSigner(paths, opts.clock);
  for (const service of SERVICE_NAMES) {
    await issueService(paths, ca, opts, service);
  }
  return SERVICE_NAMES;
}

async function main(): Promise<void> {
  const opts = readCliOptions(process.env, process.argv.slice(2));
  const rotated = await rotateServiceCerts(opts);
  process.stdout.write(`rotated: ${rotated.join(', ')} (CA untouched; restart services to load them)\n`);
}

if (require.main === module) runCli(main);
