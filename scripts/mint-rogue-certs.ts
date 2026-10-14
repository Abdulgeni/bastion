import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spiffeIdFor } from '../libs/bastion-common/src/identity/spiffe';
import { createSelfSigned, issueLeaf, type Credential, type LeafOptions } from './pki/issue';
import { readCliOptions, runCli, type PkiOptions } from './pki/cli-options';
import { pkiPaths, readCaSigner, writePrivate, writePublic, type PkiPaths } from './pki/layout';

export const ROGUE_SPIFFE_ID = 'spiffe://rogue.local/services/rogue';

export interface RogueResult {
  readonly dir: string;
  /** The identity the self-signed cert claims (edge's), to show a claim alone is not enough. */
  readonly selfSignedClaims: string;
  /** The identity on the CA-signed cert from the wrong trust domain. */
  readonly wrongIdClaims: string;
}

function writeCredential(paths: PkiPaths, kind: 'self-signed' | 'wrong-id', cred: Credential): void {
  writePrivate(paths.rogueFile(kind, 'key.pem'), cred.keyPem);
  writePublic(paths.rogueFile(kind, 'cert.pem'), cred.certPem);
}

/**
 * Mints the two attacker credentials for the rogue demo into var/rogue/:
 *  - self-signed/: a self-signed cert claiming edge's SPIFFE ID (rejected at the CA check);
 *  - wrong-id/: a cert signed by the REAL dev CA but for spiffe://rogue.local/... (a stolen
 *    or mis-issued cert: valid chain, wrong identity).
 * var/rogue/ also gets a copy of the public CA cert so the rogue can verify servers.
 * It never contains the CA private key.
 */
export async function mintRogueCerts(opts: PkiOptions): Promise<RogueResult> {
  const paths = pkiPaths(opts.varDir);
  const ca = await readCaSigner(paths, opts.clock);
  const ttlMs = opts.certTtlHours * 3_600_000;
  const edgeId = spiffeIdFor(opts.trustDomain, 'edge');
  const forged: LeafOptions = {
    commonName: 'edge', spiffeId: edgeId, dnsNames: ['edge'], ipAddresses: [], ttlMs,
  };
  const stolen: LeafOptions = {
    commonName: 'rogue', spiffeId: ROGUE_SPIFFE_ID, dnsNames: ['rogue'], ipAddresses: [], ttlMs,
  };
  writeCredential(paths, 'self-signed', await createSelfSigned(opts, forged));
  writeCredential(paths, 'wrong-id', await issueLeaf(opts, ca, stolen));
  const caCopy = `${paths.rogueDir}/ca.pem`;
  mkdirSync(dirname(caCopy), { recursive: true });
  copyFileSync(paths.caCert, caCopy);
  return { dir: paths.rogueDir, selfSignedClaims: edgeId, wrongIdClaims: ROGUE_SPIFFE_ID };
}

async function main(): Promise<void> {
  const opts = readCliOptions(process.env, process.argv.slice(2));
  const r = await mintRogueCerts(opts);
  process.stdout.write(`rogue credentials written to ${r.dir}\n`);
  process.stdout.write(`  self-signed/ claims ${r.selfSignedClaims}\n`);
  process.stdout.write(`  wrong-id/    claims ${r.wrongIdClaims} (signed by the real CA)\n`);
}

if (require.main === module) runCli(main);
