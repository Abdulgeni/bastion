import type { JWK } from 'jose';
import type { JwtKeyStore } from './key-store';

/** A JWKS document as exposed on /.well-known/jwks.json. */
export interface Jwks {
  readonly keys: readonly JWK[];
}

/** Build the JWKS for every key in the store, sorted by kid for determinism. */
export function buildJwks(store: JwtKeyStore): Jwks {
  return { keys: store.all().map((k) => k.publicJwk) };
}
