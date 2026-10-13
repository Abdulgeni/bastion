import { SetMetadata } from '@nestjs/common';
import type { ServiceName } from '../config/config';

export const ALLOW_CALLERS_KEY = 'bastion:allow-callers';

/**
 * Declares which services may call a route (or every route of a controller).
 * Enforced by PeerIdentityGuard against the caller's SPIFFE URI SAN.
 */
export const AllowCallers = (...services: ServiceName[]): ReturnType<typeof SetMetadata> =>
  SetMetadata(ALLOW_CALLERS_KEY, services);
