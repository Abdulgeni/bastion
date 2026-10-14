import { createPrivateKey, generateKeyPairSync, webcrypto } from 'node:crypto';
import { CsprngRandom, SeededRandom } from '../../libs/bastion-common/src/random/random-source';
import { deriveEd25519Keys, importSigningKey } from './keys';

describe('deriveEd25519Keys', () => {
  it('is reproducible for the same seed and differs across seeds', async () => {
    const a = await deriveEd25519Keys(new SeededRandom('s1'));
    const b = await deriveEd25519Keys(new SeededRandom('s1'));
    const c = await deriveEd25519Keys(new SeededRandom('s2'));
    expect(a.privateKeyPem).toBe(b.privateKeyPem);
    expect(a.privateKeyPem).not.toBe(c.privateKeyPem);
  });

  it('gives different keys from the CSPRNG each time', async () => {
    const random = new CsprngRandom();
    const a = await deriveEd25519Keys(random);
    const b = await deriveEd25519Keys(random);
    expect(a.privateKeyPem).not.toBe(b.privateKeyPem);
  });

  it('produces a matching Ed25519 pair whose signatures are deterministic', async () => {
    const keys = await deriveEd25519Keys(new SeededRandom('s1'));
    const data = Buffer.from('bastion');
    const sig1 = await webcrypto.subtle.sign('Ed25519', keys.privateKey, data);
    const sig2 = await webcrypto.subtle.sign('Ed25519', keys.privateKey, data);
    expect(Buffer.from(sig1).equals(Buffer.from(sig2))).toBe(true);
    expect(await webcrypto.subtle.verify('Ed25519', keys.publicKey, sig1, data)).toBe(true);
  });

  it('exports a PKCS#8 PEM that Node reads as an Ed25519 key', async () => {
    const keys = await deriveEd25519Keys(new SeededRandom('s1'));
    expect(keys.privateKeyPem).toContain('BEGIN PRIVATE KEY');
    expect(createPrivateKey(keys.privateKeyPem).asymmetricKeyType).toBe('ed25519');
  });
});

describe('importSigningKey', () => {
  it('round-trips a derived key', async () => {
    const keys = await deriveEd25519Keys(new SeededRandom('s1'));
    const imported = await importSigningKey(keys.privateKeyPem);
    const sig = await webcrypto.subtle.sign('Ed25519', imported, Buffer.from('x'));
    expect(await webcrypto.subtle.verify('Ed25519', keys.publicKey, sig, Buffer.from('x'))).toBe(
      true,
    );
  });

  it('rejects keys that are not Ed25519', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    await expect(importSigningKey(pem)).rejects.toThrow(/Ed25519/);
  });
});
