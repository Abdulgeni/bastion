import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import { JwtKeyStore } from '../libs/bastion-common/src/jwt/key-store';
import { SeededRandom } from '../libs/bastion-common/src/random/random-source';
import { readTree, testOptions, tmpVar } from './pki/test-helpers';
import { ensureJwtKeyRing, rotateJwtKey } from './rotate-jwt';

const FIXED_NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const fixed = (seed: string) => ({ random: new SeededRandom(seed), clock: new FakeClock(FIXED_NOW) });
// NTFS does not report POSIX mode bits; the assertion is POSIX-only.
const posixOnly = process.platform === 'win32' ? it.skip : it;

describe('ensureJwtKeyRing', () => {
  it('creates the first key once, then leaves the ring alone', () => {
    const dir = tmpVar();
    const opts = testOptions(dir, fixed('ensure'));

    const first = ensureJwtKeyRing(opts);
    expect(first.created).toBe(true);

    const second = ensureJwtKeyRing(opts);
    expect(second).toEqual({ created: false, kid: first.kid });
  });

  posixOnly('writes the PEM with mode 0600', () => {
    const dir = tmpVar();
    const { kid } = ensureJwtKeyRing(testOptions(dir, fixed('mode')));
    const pemPath = join(dir, 'jwt', `${kid}.pem`);
    expect(statSync(pemPath).mode & 0o777).toBe(0o600);
  });
});

describe('rotateJwtKey', () => {
  it('creates the ring when absent, with no previous kid', () => {
    const dir = tmpVar();
    const r = rotateJwtKey(testOptions(dir, fixed('first')));
    expect(r.previousKid).toBeUndefined();
    expect(readFileSync(join(dir, 'jwt', `${r.kid}.pem`), 'utf8')).toContain('BEGIN PRIVATE KEY');
  });

  it('adds a new key and retires the previous one', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir, fixed('seq'));
    const a = rotateJwtKey(opts);
    const b = rotateJwtKey(opts);
    expect(b.kid).not.toBe(a.kid);
    expect(b.previousKid).toBe(a.kid);

    // The retired map names the first kid.
    const retired = JSON.parse(
      readFileSync(join(dir, 'jwt', 'retired.json'), 'utf8'),
    ) as Record<string, number>;
    expect(retired[a.kid]).toBe(Math.floor(FIXED_NOW / 1000));
    expect(retired[b.kid]).toBeUndefined();

    // Both keys are on disk and the store lists both. Which one is "current"
    // is decided by JwtKeyStore's documented rule (lexicographically largest
    // filename), not by rotation order, so we do not assert a specific kid.
    const store = await JwtKeyStore.load(dir);
    expect(store.all().map((k) => k.kid).sort()).toEqual([a.kid, b.kid].sort());
    expect([a.kid, b.kid]).toContain(store.currentKid);
    expect(store.get(a.kid)).toBeDefined();
    expect(store.get(b.kid)).toBeDefined();
  });

  it('prunes keys whose tokens can no longer be alive', () => {
    const dir = tmpVar();
    const clock = new FakeClock(FIXED_NOW);
    const opts = { ...testOptions(dir), clock, random: new SeededRandom('prune') };
    rotateJwtKey(opts);
    clock.advanceMs(60_000);
    rotateJwtKey(opts);
    clock.advanceMs((300 + 60 + 10) * 1000);
    rotateJwtKey(opts);

    const retired = JSON.parse(
      readFileSync(join(dir, 'jwt', 'retired.json'), 'utf8'),
    ) as Record<string, number>;
    // Only the immediately previous key should still be inside the grace window.
    expect(Object.keys(retired).length).toBe(1);
  });

  it('is byte-identical across runs with the same seed and clock, and differs otherwise', () => {
    const run = (seed: string) => {
      const dir = tmpVar();
      rotateJwtKey(testOptions(dir, fixed(seed)));
      rotateJwtKey(testOptions(dir, fixed(seed)));
      return readTree(dir);
    };
    expect(run('s1')).toEqual(run('s1'));
    expect(run('s1')).not.toEqual(run('s2'));
  });

  it('produces a key store the verifier can resolve tokens against', async () => {
    const dir = tmpVar();
    rotateJwtKey(testOptions(dir, fixed('e2e')));
    const store = await JwtKeyStore.load(dir);
    expect(store.current().publicJwk).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      kid: store.currentKid,
    });
  });
});
