import type { VaultClient } from '../apps/payments/src/vault/vault.client';

/**
 * A VaultClient stand-in for e2e and integration tests. Returns a fixed
 * (per-instance) random key on `randomBytes` and a fixed lease on `login`.
 *
 * The class extends VaultClient structurally (TypeScript sees it as a
 * VaultClient) but only implements the two methods KeyHolder uses. The e2e
 * passes it to `PaymentsAppModule.forRoot(config, { vaultClient })`, which
 * uses it as the DI value for `VaultClient`.
 */
export function makeFakeVaultClient(bytesPerCall = 32): VaultClient {
  let n = 0;
  const fake = {
    async login(): Promise<{ token: string; leaseDurationSeconds: number }> {
      return { token: 'fake-token', leaseDurationSeconds: 3_600 };
    },
    async randomBytes(): Promise<Buffer> {
      n += 1;
      // Deterministic but varying per call, so rotation changes the fingerprint.
      const key = Buffer.alloc(bytesPerCall, (n * 0x11) & 0xff);
      return key;
    },
  };
  return fake as unknown as VaultClient;
}
