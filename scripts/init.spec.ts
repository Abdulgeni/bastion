import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initMaterial, readRootToken } from './init';

describe('initMaterial', () => {
  it('creates the vault files and the jwt key ring on a fresh var dir', () => {
    const varDir = mkdtempSync(join(tmpdir(), 'bastion-init-'));
    const result = initMaterial(varDir);
    expect(result.created.length).toBeGreaterThanOrEqual(4); // root-token, policy, credentials, jwt current
    expect(existsSync(join(varDir, 'vault', 'root-token'))).toBe(true);
    expect(existsSync(join(varDir, 'vault', 'policy.hcl'))).toBe(true);
    expect(existsSync(join(varDir, 'demo', 'credentials.json'))).toBe(true);
    expect(existsSync(join(varDir, 'jwt', 'current'))).toBe(true);
    const token = readRootToken(varDir);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('leaves existing files alone on a second call', () => {
    const varDir = mkdtempSync(join(tmpdir(), 'bastion-init-'));
    initMaterial(varDir);
    const firstToken = readRootToken(varDir);
    const second = initMaterial(varDir);
    expect(second.created).toEqual([]);
    expect(readRootToken(varDir)).toBe(firstToken);
  });

  it('writes the Vault policy with `update` on sys/tools/random (F4)', () => {
    const varDir = mkdtempSync(join(tmpdir(), 'bastion-init-'));
    initMaterial(varDir);
    const policy = readFileSync(join(varDir, 'vault', 'policy.hcl'), 'utf8');
    expect(policy).toContain('capabilities = ["update"]');
    expect(policy).toContain('sys/tools/random');
  });

  // NTFS does not honor POSIX mode bits; the assertion is POSIX-only.
  const posixOnly = process.platform === 'win32' ? it.skip : it;
  posixOnly('writes the demo credentials with mode 0600', () => {
    const varDir = mkdtempSync(join(tmpdir(), 'bastion-init-'));
    initMaterial(varDir);
    expect(statSync(join(varDir, 'demo', 'credentials.json')).mode & 0o777).toBe(0o600);
  });
});
