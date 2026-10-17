import { Test } from '@nestjs/testing';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BastionModule } from './bastion.module';
import { BASTION_CONFIG, CLOCK, JWT_VERIFIER, RANDOM } from '../tokens';
import { AuditService } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';
import { AccessRecorder } from '../audit/access-recorder';
import { PeerIdentityGuard } from '../identity/peer-identity.guard';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { TokenVerifier } from '../jwt/verifier';
import { JwtKeyStore, generateSigningKeyPem } from '../jwt/key-store';
import { TokenIssuer } from '../jwt/issuer';
import { SeededRandom } from '../random/random-source';
import type { BastionConfig } from '../config/config';

function config(over: Partial<BastionConfig> = {}): BastionConfig {
  return {
    serviceName: 'orders',
    nodeEnv: 'test',
    trustDomain: 'bastion.local',
    logLevel: 'info',
    data: { host: '127.0.0.1', port: 8443 },
    mgmt: { host: '127.0.0.1', port: 9091 },
    tls: { certFile: '/tmp/c', keyFile: '/tmp/k', caFile: '/tmp/a' },
    auditDir: '/tmp/audit',
    jwt: { jwksUrl: 'http://127.0.0.1:9/jwks', replayCacheSize: 1000, keyStoreDir: '/tmp/jwt' },
    isEdge: false,
    serviceUrls: {
      edge: 'https://edge:8080',
      orders: 'https://orders:8443',
      inventory: 'https://inventory:8444',
      payments: 'https://payments:8445',
    },
    ...over,
  };
}

async function build(cfg: BastionConfig) {
  const moduleRef = await Test.createTestingModule({
    imports: [BastionModule.forRoot({ config: cfg })],
  }).compile();
  return moduleRef;
}

describe('BastionModule: common providers', () => {
  it('provides every shared service and guard for a non-edge service', async () => {
    const m = await build(config({ serviceName: 'orders' }));
    expect(m.get(BASTION_CONFIG)).toMatchObject({ serviceName: 'orders' });
    expect(m.get(CLOCK)).toBeDefined();
    expect(m.get(RANDOM)).toBeDefined();
    expect(m.get(AuditService)).toBeInstanceOf(AuditService);
    expect(m.get(MetricsService)).toBeInstanceOf(MetricsService);
    expect(m.get(AccessRecorder)).toBeInstanceOf(AccessRecorder);
    expect(m.get(JWT_VERIFIER)).toBeInstanceOf(TokenVerifier);
    expect(m.get(PeerIdentityGuard)).toBeInstanceOf(PeerIdentityGuard);
    expect(m.get(JwtAuthGuard)).toBeInstanceOf(JwtAuthGuard);
  });

  it('does not register edge-only providers on a non-edge service', async () => {
    const m = await build(config({ serviceName: 'orders' }));
    expect(() => m.get(TokenIssuer)).toThrow();
    expect(() => m.get(JwtKeyStore)).toThrow();
  });
});

describe('BastionModule: edge providers', () => {
  it('provides JwtKeyStore and TokenIssuer for edge', async () => {
    // Give the key store a real key on disk so JwtKeyStore.load() succeeds.
    const dir = mkdtempSync(join(tmpdir(), 'bastion-mod-'));
    mkdirSync(join(dir, 'jwt'), { recursive: true });
    const random = new SeededRandom('module-edge');
    const { kid, pem } = generateSigningKeyPem(random);
    writeFileSync(join(dir, 'jwt', `${kid}.pem`), pem, { mode: 0o600 });
    writeFileSync(join(dir, 'jwt', 'current'), `${kid}\n`, { mode: 0o600 });

    const cfg = config({
      serviceName: 'edge',
      isEdge: true,
      data: { host: '127.0.0.1', port: 8080 },
      mgmt: { host: '127.0.0.1', port: 9090 },
      jwt: { jwksUrl: 'http://127.0.0.1:9/jwks', replayCacheSize: 1000, keyStoreDir: join(dir, 'jwt') },
    });
    const m = await build(cfg);
    expect(m.get(JwtKeyStore)).toBeInstanceOf(JwtKeyStore);
    expect(m.get(TokenIssuer)).toBeInstanceOf(TokenIssuer);
  });
});
