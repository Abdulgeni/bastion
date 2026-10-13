import { join } from 'node:path';
import { ConfigError } from '../errors';
import { loadConfig } from './config';

const base = {
  SERVICE_NAME: 'orders',
  NODE_ENV: 'test',
  DATA_BIND_ADDR: '10.0.1.5',
  MGMT_BIND_ADDR: '10.0.9.5',
};

function configError(env: Record<string, string | undefined>): ConfigError {
  try {
    loadConfig(env);
  } catch (e) {
    return e as ConfigError;
  }
  throw new Error('expected loadConfig to throw');
}

describe('loadConfig', () => {
  it('applies per-service defaults', () => {
    const cfg = loadConfig(base);
    expect(cfg.serviceName).toBe('orders');
    expect(cfg.data).toEqual({ host: '10.0.1.5', port: 8443 });
    expect(cfg.mgmt).toEqual({ host: '10.0.9.5', port: 9091 });
    expect(cfg.trustDomain).toBe('bastion.local');
    expect(cfg.logLevel).toBe('info');
    expect(cfg.tls.certFile).toBe(join('./var', 'certs', 'orders', 'cert.pem'));
    expect(cfg.tls.caFile).toBe(join('./var', 'ca', 'ca.pem'));
    expect(cfg.auditDir).toBe(join('./var', 'audit'));
    expect(cfg.testSeed).toBeUndefined();
  });

  it('honours overrides', () => {
    const cfg = loadConfig({
      ...base,
      DATA_PORT: '9443',
      BASTION_VAR_DIR: '/x',
      TLS_CA_FILE: '/pki/ca.pem',
      LOG_LEVEL: 'debug',
    });
    expect(cfg.data.port).toBe(9443);
    expect(cfg.tls.keyFile).toBe(join('/x', 'certs', 'orders', 'key.pem'));
    expect(cfg.tls.caFile).toBe('/pki/ca.pem');
    expect(cfg.logLevel).toBe('debug');
  });

  it.each([
    ['missing SERVICE_NAME', { ...base, SERVICE_NAME: undefined }],
    ['unknown service', { ...base, SERVICE_NAME: 'billing' }],
    ['missing NODE_ENV', { ...base, NODE_ENV: undefined }],
    ['missing data bind address', { ...base, DATA_BIND_ADDR: undefined }],
    ['invalid mgmt bind address', { ...base, MGMT_BIND_ADDR: 'not-an-ip' }],
    ['non-numeric port', { ...base, DATA_PORT: 'abc' }],
    ['out-of-range port', { ...base, MGMT_PORT: '70000' }],
    ['bad log level', { ...base, LOG_LEVEL: 'loud' }],
    ['empty seed', { ...base, BASTION_TEST_SEED: '' }],
  ])('rejects %s', (_name, env) => {
    expect(() => loadConfig(env)).toThrow(ConfigError);
  });

  it('refuses a test seed in production without echoing it', () => {
    const err = configError({ ...base, NODE_ENV: 'production', BASTION_TEST_SEED: 's3cr3t-seed' });
    expect(err.message).toMatch(/BASTION_TEST_SEED/);
    expect(err.message).not.toContain('s3cr3t-seed');
  });

  it('accepts a test seed outside production', () => {
    expect(loadConfig({ ...base, BASTION_TEST_SEED: 'seed' }).testSeed).toBe('seed');
  });

  it('does not echo invalid values in error messages', () => {
    expect(configError({ ...base, DATA_PORT: 'abc' }).message).not.toContain('abc');
  });
});
