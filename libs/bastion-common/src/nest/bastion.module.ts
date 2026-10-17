import { DynamicModule, Module, type Provider } from '@nestjs/common';
import { join } from 'node:path';
import { SystemClock, type Clock } from '../clock/clock';
import { createRandomSource, type RandomSource } from '../random/random-source';
import { BASTION_CONFIG, CLOCK, JWT_VERIFIER, RANDOM } from '../tokens';
import { AuditService, FileAuditSink, StreamAuditSink } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';
import { AccessRecorder } from '../audit/access-recorder';
import { PEER_DECISION_LISTENER, PeerIdentityGuard } from '../identity/peer-identity.guard';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { JwksCache } from '../jwt/jwks-cache';
import { ReplayCache } from '../jwt/replay-cache';
import { TokenVerifier } from '../jwt/verifier';
import { JwtKeyStore } from '../jwt/key-store';
import { TokenIssuer } from '../jwt/issuer';
import type { BastionConfig } from '../config/config';

export interface BastionModuleOptions {
  readonly config: BastionConfig;
}

/** Every shared provider the module exports. */
const COMMON_EXPORTS = [
  BASTION_CONFIG,
  CLOCK,
  RANDOM,
  AuditService,
  MetricsService,
  AccessRecorder,
  PEER_DECISION_LISTENER,
  JWT_VERIFIER,
  PeerIdentityGuard,
  JwtAuthGuard,
] as const;

/** Config, clock, and random source: the primitives every other provider uses. */
function coreProviders(config: BastionConfig): Provider[] {
  return [
    { provide: BASTION_CONFIG, useValue: config },
    { provide: CLOCK, useFactory: () => new SystemClock() },
    {
      provide: RANDOM,
      useFactory: (cfg: BastionConfig) =>
        createRandomSource({ nodeEnv: cfg.nodeEnv, seed: cfg.testSeed }),
      inject: [BASTION_CONFIG],
    },
  ];
}

/** Audit, metrics, and the recorder that writes both from every decision. */
function observabilityProviders(): Provider[] {
  return [
    {
      provide: AuditService,
      useFactory: (cfg: BastionConfig, clock: Clock) =>
        new AuditService({
          service: cfg.serviceName,
          clock,
          sinks: [
            new StreamAuditSink(process.stdout),
            new FileAuditSink(join(cfg.auditDir, `${cfg.serviceName}.log`)),
          ],
        }),
      inject: [BASTION_CONFIG, CLOCK],
    },
    {
      provide: MetricsService,
      useFactory: (cfg: BastionConfig, clock: Clock) =>
        new MetricsService(cfg.serviceName, clock),
      inject: [BASTION_CONFIG, CLOCK],
    },
    {
      provide: AccessRecorder,
      useFactory: (audit: AuditService, metrics: MetricsService) =>
        new AccessRecorder(audit, metrics),
      inject: [AuditService, MetricsService],
    },
    { provide: PEER_DECISION_LISTENER, useExisting: AccessRecorder },
  ];
}

/** The token verifier and the two guards that consume it. */
function authProviders(): Provider[] {
  return [
    {
      provide: JWT_VERIFIER,
      useFactory: (cfg: BastionConfig, clock: Clock) => {
        const jwks = new JwksCache({ url: cfg.jwt.jwksUrl, http: httpClient(), clock });
        const replay = new ReplayCache(clock, { capacity: cfg.jwt.replayCacheSize });
        return new TokenVerifier({
          serviceName: cfg.serviceName,
          expectedAudience: cfg.isEdge ? 'edge' : cfg.serviceName,
          expectedIssuer: 'edge',
          clock,
          jwks,
          replay,
          skipAudienceCheck: cfg.isEdge || cfg.serviceName === 'edge',
        });
      },
      inject: [BASTION_CONFIG, CLOCK],
    },
    PeerIdentityGuard,
    JwtAuthGuard,
  ];
}

/** Providers wired for every service, edge or not. */
function commonProviders(config: BastionConfig): Provider[] {
  return [...coreProviders(config), ...observabilityProviders(), ...authProviders()];
}

/** Extra providers only edge gets: the JWT signing key store and issuer. */
function edgeOnlyProviders(): Provider[] {
  return [
    {
      provide: JwtKeyStore,
      useFactory: (cfg: BastionConfig) => JwtKeyStore.loadFromDir(cfg.jwt.keyStoreDir),
      inject: [BASTION_CONFIG],
    },
    {
      provide: TokenIssuer,
      useFactory: (store: JwtKeyStore, clock: Clock, random: RandomSource) =>
        new TokenIssuer(store, clock, random),
      inject: [JwtKeyStore, CLOCK, RANDOM],
    },
  ];
}

/**
 * DI module that wires the shared cross-cutting concerns: clock, random, audit,
 * metrics, the access recorder, the token verifier, and both guards. Edge-only
 * providers (the key store and token issuer) are registered only when
 * `config.isEdge` is true.
 */
@Module({})
export class BastionModule {
  static forRoot(opts: BastionModuleOptions): DynamicModule {
    const config = opts.config;
    return {
      module: BastionModule,
      providers: [...commonProviders(config), ...(config.isEdge ? edgeOnlyProviders() : [])],
      exports: [...COMMON_EXPORTS, ...(config.isEdge ? [JwtKeyStore, TokenIssuer] : [])],
    };
  }
}

/** The `JwksCache` HTTP client shape: parses JSON, bounded time, no redirects. */
function httpClient(): { getJson(url: string): Promise<unknown> } {
  return {
    async getJson(url: string): Promise<unknown> {
      const res = await fetch(url, { signal: AbortSignal.timeout(2_000), redirect: 'error' });
      if (!res.ok) throw new Error(`JWKS endpoint returned ${res.status}`);
      return res.json();
    },
  };
}
