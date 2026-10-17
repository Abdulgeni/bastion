import { Module, type DynamicModule, type Provider } from '@nestjs/common';
import {
  BASTION_CONFIG,
  CLOCK,
  BastionModule,
  MetricsService,
  type BastionConfig,
  type Clock,
} from '@bastion/common';
import { readFileSync } from 'node:fs';
import { ChargeController } from './charge/charge.controller';
import { ChargeService } from './charge/charge.service';
import { VaultClient } from './vault/vault.client';
import { KeyHolder } from './vault/key-holder';

export interface PaymentsModuleOptions {
  /** Test-only: replace the real Vault client with an in-process fake. */
  readonly vaultClient?: VaultClient;
  /** Test-only: override the AppRole credentials normally read from disk. */
  readonly appRole?: { readonly roleId: string; readonly secretId: string };
}

/** The VaultClient provider. Uses the override when one is supplied. */
function vaultClientProvider(override: VaultClient | undefined): Provider {
  if (override) return { provide: VaultClient, useValue: override };
  return {
    provide: VaultClient,
    useFactory: (cfg: BastionConfig) => {
      if (cfg.vault === undefined) throw new Error('payments requires config.vault');
      return new VaultClient(cfg.vault);
    },
    inject: [BASTION_CONFIG],
  };
}

/** Reads role_id/secret_id from the override or the files the init script wrote. */
function credentials(
  cfg: BastionConfig,
  override: PaymentsModuleOptions['appRole'],
): { roleId: string; secretId: string } {
  if (cfg.vault === undefined) throw new Error('payments requires config.vault');
  return {
    roleId: override?.roleId ?? readFileSync(cfg.vault.roleIdFile, 'utf8').trim(),
    secretId: override?.secretId ?? readFileSync(cfg.vault.wrappedSecretIdFile, 'utf8').trim(),
  };
}

/** Boots one KeyHolder: fetches the first key (fail-to-start) and installs the refresh timer. */
function keyHolderProvider(override: PaymentsModuleOptions['appRole']): Provider {
  return {
    provide: KeyHolder,
    useFactory: async (
      vault: VaultClient,
      cfg: BastionConfig,
      clock: Clock,
      metrics: MetricsService,
    ) => {
      const { roleId, secretId } = credentials(cfg, override);
      const holder = new KeyHolder({
        vault,
        clock,
        metrics,
        ttlMs: (cfg.vault?.keyTtlSeconds ?? 10) * 1_000,
        roleId,
        secretId,
      });
      await holder.start();
      return holder;
    },
    inject: [VaultClient, BASTION_CONFIG, CLOCK, MetricsService],
  };
}

@Module({})
export class PaymentsAppModule {
  static forRoot(config: BastionConfig, options: PaymentsModuleOptions = {}): DynamicModule {
    return {
      module: PaymentsAppModule,
      imports: [BastionModule.forRoot({ config })],
      controllers: [ChargeController],
      providers: [
        vaultClientProvider(options.vaultClient),
        keyHolderProvider(options.appRole),
        ChargeService,
      ],
    };
  }
}
