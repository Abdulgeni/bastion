import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { extractUriSans } from '../libs/bastion-common/src/identity/san';
import { generateAll } from './gen-certs';
import { pkiPaths } from './pki/layout';
import {
  mtlsCall,
  readTree,
  startOrdersServer,
  testOptions,
  tmpVar,
  waitForRejections,
} from './pki/test-helpers';
import { ROGUE_SPIFFE_ID, mintRogueCerts } from './mint-rogue-certs';

const cert = (path: string) => new X509Certificate(readFileSync(path));

describe('mintRogueCerts', () => {
  it('writes a self-signed cert claiming edge and a real-CA cert claiming the rogue ID', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    const result = await mintRogueCerts(opts);
    const p = pkiPaths(dir);
    const caPublicKey = cert(p.caCert).publicKey;

    const selfSigned = cert(p.rogueFile('self-signed', 'cert.pem'));
    expect(selfSigned.verify(caPublicKey)).toBe(false);
    expect(extractUriSans(selfSigned.subjectAltName)).toEqual([result.selfSignedClaims]);
    expect(result.selfSignedClaims).toBe('spiffe://bastion.local/services/edge');

    const wrongId = cert(p.rogueFile('wrong-id', 'cert.pem'));
    expect(wrongId.verify(caPublicKey)).toBe(true);
    expect(extractUriSans(wrongId.subjectAltName)).toEqual([ROGUE_SPIFFE_ID]);
  });

  it('never puts the CA private key (or any service key) in var/rogue', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    await mintRogueCerts(opts);
    const rogueFiles = Object.keys(readTree(pkiPaths(dir).rogueDir)).sort();
    expect(rogueFiles).toEqual([
      'ca.pem',
      'self-signed/cert.pem',
      'self-signed/key.pem',
      'wrong-id/cert.pem',
      'wrong-id/key.pem',
    ]);
  });

  it('needs an existing CA', async () => {
    await expect(mintRogueCerts(testOptions(tmpVar()))).rejects.toThrow(/no CA found/);
  });

  it('is rejected by orders exactly as the rogue demo expects', async () => {
    const dir = tmpVar();
    const opts = testOptions(dir);
    await generateAll(opts);
    await mintRogueCerts(opts);
    const p = pkiPaths(dir);
    const server = await startOrdersServer(dir, opts.clock);
    const ca = p.rogueFile('self-signed', 'cert.pem').replace(/self-signed.cert\.pem$/, 'ca.pem');

    await expect(
      mtlsCall(server.port, {
        cert: p.rogueFile('self-signed', 'cert.pem'),
        key: p.rogueFile('self-signed', 'key.pem'),
        ca,
      }),
    ).rejects.toThrow();
    await waitForRejections(server, 1);
    expect(server.rejections[0]).toMatchObject({
      reason: 'mtls+rejected_ca',
      detail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
    });

    const reply = await mtlsCall(server.port, {
      cert: p.rogueFile('wrong-id', 'cert.pem'),
      key: p.rogueFile('wrong-id', 'key.pem'),
      ca,
    });
    await server.close();
    expect(reply.status).toBe(401);
    expect(reply.body).toMatchObject({
      reason: 'mtls+bad-identity',
      identity: { trustDomain: 'rogue.local', service: 'rogue' },
    });
  });
});
