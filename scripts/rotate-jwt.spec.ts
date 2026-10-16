import { readFileSync, statSync } from 'node:fs';
import { FakeClock } from '../libs/bastion-common/src/clock/clock';
import {
  defaultKeyRingPath,
  publicJwks,
  readKeyRingFile,
} from '../libs/bastion-common/src/jwt/key-ring';
import { JwtIssuer } from '../libs/bastion-common/src/jwt/issuer';
import { NOW, makeWorld } from '../libs/bastion-common/src/jwt/test-helpers';
import { SeededRandom } from '../libs/bastion-common/src/random/random-source';
import { readTree, testOptions, tmpVar } from './pki/test-helpers';
import { ensureJwtKeyRing, rotateJwtKey } from './rotate-jwt';

const fixed = (seed: string) => ({ random: new SeededRandom(seed), clock: new FakeClock(NOW) });
// NTFS does not report POSIX mode bits; the assertion is POSIX-only.
const posixOnly = process.platform === 'win32' ? it.skip : it;

describe('ensureJwtKeyRing', () => {
  it('creates a 0600 key ring once and then leaves it alone', () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    const first = ensureJwtKeyRing(opts);
    const path = defaultKeyRingPath(dir);
    const before = readFileSync(path, 'utf8');
    expect(first.created).toBe(true);
    if (process.platform !== 'win32') {
      expect(statSync(path).mode & 0o777).toBe(0o600);
    }

    const second = ensureJwtKeyRing(opts);
    expect(second).toEqual({ created: false, kid: first.kid });
    expect(readFileSync(path, 'utf8')).toBe(before);
  });
});

describe('rotateJwtKey', () => {
  it('creates the ring when absent, with no previous kid', () => {
    const dir = tmpVar();
    const r = rotateJwtKey(testOptions(dir));
    expect(r.previousKid).toBeUndefined();
    expect(r.keyCount).toBe(1);
    expect(readKeyRingFile(defaultKeyRingPath(dir)).active).toBe(r.kid);
  });

  it('adds a new active key and keeps the previous one published', () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    const a = rotateJwtKey(opts);
    const b = rotateJwtKey(opts);
    expect(b.kid).not.toBe(a.kid);
    expect(b.previousKid).toBe(a.kid);
    expect(b.keyCount).toBe(2);
    const ring = readKeyRingFile(defaultKeyRingPath(dir));
    const published = publicJwks(ring, opts.clock.nowMs()).keys.map((k) => k.kid);
    expect(published).toEqual([b.kid, a.kid]);
  });

  it('drops keys whose tokens can no longer be alive', () => {
    const dir = tmpVar();
    const clock = new FakeClock(NOW);
    const opts = testOptions(dir, { clock });
    rotateJwtKey(opts);
    clock.advanceMs(60_000);
    rotateJwtKey(opts);
    clock.advanceMs(10 * 60_000);
    expect(rotateJwtKey(opts).keyCount).toBe(2);
  });

  it('is byte-identical across runs with the same seed and clock', () => {
    const run = (seed: string) => {
      const dir = tmpVar();
      rotateJwtKey(testOptions(dir, fixed(seed)));
      rotateJwtKey(testOptions(dir, fixed(seed)));
      return readTree(dir);
    };
    expect(run('s1')).toEqual(run('s1'));
    expect(run('s1')).not.toEqual(run('s2'));
  });

  it('produces a ring whose tokens verify through the published JWKS', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir, fixed('e2e'));
    rotateJwtKey(opts);
    const world = makeWorld({ ring: readKeyRingFile(defaultKeyRingPath(dir)) });
    expect((await world.verifier('orders').verify(await world.token())).ok).toBe(true);
    const issuer = new JwtIssuer({ ring: () => world.ring, clock: world.clock, random: world.random });
    expect((await issuer.issue({ sub: 'alice', scope: ['orders:write'] })).kid).toBe(world.ring.active);
  });
});
