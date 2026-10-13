import type { Clock } from '../clock/clock';
import { MTLS_REASON, type MtlsReason } from '../mtls/reasons';
import { extractUriSans } from './san';
import { parseSpiffeId, type SpiffeId } from './spiffe';
import { certWindowState } from './validity';

/** The fields of a Node PeerCertificate that Bastion looks at. `{}` means "no certificate". */
export interface PeerCertLike {
  readonly subjectaltname?: string;
  readonly valid_from?: string;
  readonly valid_to?: string;
}

export type PeerCheck =
  | { readonly ok: true; readonly identity: SpiffeId }
  | { readonly ok: false; readonly reason: MtlsReason; readonly identity?: SpiffeId };

export interface PeerCheckInput {
  readonly cert: PeerCertLike | undefined;
  readonly clock: Clock;
  /** Exact SPIFFE URIs permitted to call this route. */
  readonly allowedIds: readonly string[];
}

function fail(reason: MtlsReason, identity?: SpiffeId): PeerCheck {
  return identity ? { ok: false, reason, identity } : { ok: false, reason };
}

function hasNoCert(cert: PeerCertLike | null | undefined): boolean {
  return cert === undefined || cert === null || Object.keys(cert).length === 0;
}

/**
 * Post-handshake identity decision. Node has already verified the chain; this
 * checks, in order: certificate present, validity window (via the injected Clock),
 * exactly one well-formed SPIFFE URI SAN, and membership in the route allowlist.
 */
export function checkPeer(input: PeerCheckInput): PeerCheck {
  const { cert, clock, allowedIds } = input;
  if (hasNoCert(cert)) return fail(MTLS_REASON.NO_CLIENT_CERT);

  const window = certWindowState(clock.nowMs(), cert?.valid_from, cert?.valid_to);
  if (window === 'unparseable') return fail(MTLS_REASON.BAD_IDENTITY);
  if (window === 'outside') return fail(MTLS_REASON.EXPIRED);

  const uris = extractUriSans(cert?.subjectaltname);
  const identity = uris.length === 1 ? parseSpiffeId(uris[0]) : undefined;
  if (!identity) return fail(MTLS_REASON.BAD_IDENTITY);
  if (!allowedIds.includes(identity.uri)) return fail(MTLS_REASON.BAD_IDENTITY, identity);
  return { ok: true, identity };
}
