/** A parsed SPIFFE workload ID of the form spiffe://<trust-domain>/services/<name>. */
export interface SpiffeId {
  readonly uri: string;
  readonly trustDomain: string;
  readonly service: string;
}

const MAX_URI_LENGTH = 255;
const SERVICE_ID =
  /^spiffe:\/\/([a-z0-9]+(?:[.-][a-z0-9]+)*)\/services\/([a-z0-9]+(?:-[a-z0-9]+)*)$/;

/** Parses a SPIFFE service ID; returns undefined for anything malformed. */
export function parseSpiffeId(uri: string): SpiffeId | undefined {
  if (uri.length > MAX_URI_LENGTH) return undefined;
  const m = SERVICE_ID.exec(uri);
  if (!m) return undefined;
  return { uri, trustDomain: m[1], service: m[2] };
}

/** Builds the canonical SPIFFE ID for a service in a trust domain. */
export function spiffeIdFor(trustDomain: string, service: string): string {
  return `spiffe://${trustDomain}/services/${service}`;
}
