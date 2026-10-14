import { ConfigError } from '../../libs/bastion-common/src/errors';
import { CsprngRandom, SeededRandom } from '../../libs/bastion-common/src/random/random-source';
import { readCliOptions } from './cli-options';

describe('readCliOptions', () => {
  it('uses documented defaults and the CSPRNG', () => {
    const o = readCliOptions({}, []);
    expect(o.varDir).toBe('./var');
    expect(o.trustDomain).toBe('bastion.local');
    expect(o.certTtlHours).toBe(168);
    expect(o.caTtlDays).toBe(365);
    expect(o.forceCa).toBe(false);
    expect(o.random).toBeInstanceOf(CsprngRandom);
  });

  it('honours environment overrides, --force-ca and a test seed', () => {
    const o = readCliOptions(
      {
        BASTION_VAR_DIR: '/data/var',
        BASTION_TRUST_DOMAIN: 'corp.test',
        BASTION_CERT_TTL_HOURS: '12',
        BASTION_CA_TTL_DAYS: '10',
        NODE_ENV: 'test',
        BASTION_TEST_SEED: 'abc',
      },
      ['--force-ca'],
    );
    expect(o).toMatchObject({
      varDir: '/data/var',
      trustDomain: 'corp.test',
      certTtlHours: 12,
      caTtlDays: 10,
      forceCa: true,
    });
    expect(o.random).toBeInstanceOf(SeededRandom);
  });

  it.each([['0'], ['abc'], ['1.5'], ['-3']])('rejects a bad TTL %p', (bad) => {
    expect(() => readCliOptions({ BASTION_CERT_TTL_HOURS: bad }, [])).toThrow(
      /BASTION_CERT_TTL_HOURS/,
    );
  });

  it('refuses a test seed in production', () => {
    expect(() => readCliOptions({ NODE_ENV: 'production', BASTION_TEST_SEED: 'abc' }, [])).toThrow(
      ConfigError,
    );
  });
});
