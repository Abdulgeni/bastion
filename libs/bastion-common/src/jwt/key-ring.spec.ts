import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConfigError } from '../errors';
import { SeededRandom } from '../random/random-source';
import {
  KEY_GRACE_SECONDS,
  KeyRingFile,
  activeKey,
  generateSigningKey,
  isPublishable,
  kidFor,
  parseKeyRing,
  publicJwks,
  readKeyRingFile,
  rotateKeyRing,
  serializeKeyRing,
  type KeyRing,
} from './key-ring';
import { TOKEN_TTL_SECONDS } from './claims';

const T0 = Date.UTC(2026, 9, 12, 12, 0, 0);
const WINDOW_MS = (TOKEN_TTL_SECONDS + KEY_GRACE_SECONDS) * 1000;

function ring(...seeds: string[]): KeyRing {
  let r: KeyRing | undefined;
  seeds.forEach((s, i) => {
    r = rotateKeyRing(r, generateSigningKey(new SeededRandom(s), T0 + i), T0 + i);
  });
  return r as KeyRing;
}

describe('kidFor', () => {
  it('matches the RFC 8037 appendix A.3 thumbprint example', () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
    expect(kidFor(createPublicKey({ key: jwk, format: 'jwk' }))).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
    );
  });
});

describe('generateSigningKey', () => {
  it('is reproducible for a seed, differs across seeds, and has a 43-char base64url kid', () => {
    const a = generateSigningKey(new SeededRandom('s'), T0);
    const b = generateSigningKey(new SeededRandom('s'), T0);
    const c = generateSigningKey(new SeededRandom('t'), T0);
    expect(a.privateKeyPem).toBe(b.privateKeyPem);
    expect(a.kid).toBe(b.kid);
    expect(a.kid).not.toBe(c.kid);
    expect(a.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(createHash('sha256').update(a.privateKeyPem).digest('hex')).toHaveLength(64);
  });
});

describe('rotateKeyRing', () => {
  it('starts a ring and then retires the previous active key on rotation', () => {
    const r = ring('a', 'b');
    expect(r.keys).toHaveLength(2);
    expect(activeKey(r).kid).toBe(r.active);
    const old = r.keys.find((k) => k.kid !== r.active);
    expect(old?.retiredAtMs).toBe(T0 + 1);
    expect(activeKey(r).retiredAtMs).toBeUndefined();
  });

  it('drops keys retired longer than TTL + grace ago', () => {
    let r = ring('a', 'b');
    const later = T0 + WINDOW_MS + 10;
    r = rotateKeyRing(r, generateSigningKey(new SeededRandom('c'), later), later);
    expect(r.keys).toHaveLength(2);
    expect(r.keys.some((k) => k.retiredAtMs === T0 + 1)).toBe(false);
  });
});

describe('isPublishable and publicJwks', () => {
  it('publishes a retired key until exactly TTL + grace after retirement', () => {
    const r = ring('a', 'b');
    const old = r.keys.find((k) => k.kid !== r.active);
    if (!old) throw new Error('missing retired key');
    expect(isPublishable(old, T0 + 1 + WINDOW_MS - 1)).toBe(true);
    expect(isPublishable(old, T0 + 1 + WINDOW_MS)).toBe(false);
  });

  it('lists the active key first with public fields only', () => {
    const r = ring('a', 'b');
    const { keys } = publicJwks(r, T0 + 5);
    expect(keys.map((k) => k.kid)[0]).toBe(r.active);
    expect(keys).toHaveLength(2);
    expect(keys[0]).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig' });
    expect(JSON.stringify(keys)).not.toContain('PRIVATE');
    expect(JSON.stringify(keys)).not.toContain('"d"');
    expect(publicJwks(r, T0 + 1 + WINDOW_MS).keys).toHaveLength(1);
  });
});

describe('serialize / parse', () => {
  it('round-trips a ring', () => {
    const r = ring('a', 'b');
    const back = parseKeyRing(serializeKeyRing(r));
    expect(back.active).toBe(r.active);
    expect(back.keys.map((k) => k.kid)).toEqual(r.keys.map((k) => k.kid));
    expect(back.keys.map((k) => k.privateKeyPem)).toEqual(r.keys.map((k) => k.privateKeyPem));
  });

  const doc = () => JSON.parse(serializeKeyRing(ring('a', 'b'))) as Record<string, any>;
  const ecPem = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .privateKey.export({ format: 'pem', type: 'pkcs8' })
    .toString();

  it.each([
    ['not JSON', () => 'nope{'],
    ['wrong version', () => JSON.stringify({ ...doc(), version: 2 })],
    ['no keys', () => JSON.stringify({ ...doc(), keys: [] })],
    ['11 keys', () => JSON.stringify({ ...doc(), keys: Array.from({ length: 11 }, () => doc().keys[0]) })],
    ['active names a missing kid', () => JSON.stringify({ ...doc(), active: 'zzz' })],
    ['tampered kid', () => JSON.stringify((() => { const d = doc(); d.keys[0].kid = 'x'.repeat(43); return d; })())],
    ['non-Ed25519 key', () => JSON.stringify((() => { const d = doc(); d.keys[0].privateKeyPem = ecPem; return d; })())],
    ['two active keys', () => JSON.stringify((() => { const d = doc(); delete d.keys[1].retiredAtMs; delete d.keys[0].retiredAtMs; return d; })())],
  ])('rejects %s without echoing key material', (_name, text) => {
    let message = '';
    try {
      parseKeyRing(text());
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      message = (e as Error).message;
    }
    expect(message.length).toBeGreaterThan(0);
    expect(message).not.toContain('PRIVATE');
  });
});

describe('readKeyRingFile and KeyRingFile', () => {
  const dir = () => mkdtempSync(join(tmpdir(), 'bastion-ring-'));

  it('reports a missing file as ConfigError', () => {
    expect(() => readKeyRingFile(join(dir(), 'keys.json'))).toThrow(/cannot read/);
    expect(() => readKeyRingFile(join(dir(), 'keys.json'))).toThrow(ConfigError);
  });

  it('re-reads only when the file changes, and fails loudly on a corrupt file', () => {
    const path = join(dir(), 'keys.json');
    writeFileSync(path, serializeKeyRing(ring('a')));
    const file = new KeyRingFile(path);
    const first = file.get();
    expect(file.get()).toBe(first);
    writeFileSync(path, serializeKeyRing(ring('a', 'b')));
    expect(file.get().keys).toHaveLength(2);
    writeFileSync(path, 'corrupt');
    expect(() => file.get()).toThrow(ConfigError);
  });
});
