import { EventEmitter } from 'node:events';
import type { Server as HttpsServer } from 'node:https';
import { attachTlsClientErrorHandler, classifyTlsError, type TlsRejection } from './tls-errors';

describe('classifyTlsError', () => {
  it.each([
    ['ECONNRESET', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'mtls+rejected_ca'],
    ['ECONNRESET', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'mtls+rejected_ca'],
    ['ECONNRESET', 'CERT_HAS_EXPIRED', 'mtls+expired'],
    ['ECONNRESET', 'CERT_NOT_YET_VALID', 'mtls+expired'],
    ['ERR_SSL_PEER_DID_NOT_RETURN_A_CERTIFICATE', null, 'mtls+no-client-cert'],
    ['ERR_SSL_HTTP_REQUEST', null, 'mtls+handshake-error'],
    ['ECONNRESET', undefined, 'mtls+handshake-error'],
  ])('maps code=%s auth=%s to %s', (code, auth, reason) => {
    expect(classifyTlsError(code, auth).reason).toBe(reason);
  });

  it('accepts an Error carrying a code as the authorization error', () => {
    const auth = Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' });
    expect(classifyTlsError('ECONNRESET', auth)).toEqual({
      reason: 'mtls+expired',
      detail: 'CERT_HAS_EXPIRED',
    });
  });

  it('never echoes attacker-controlled text as the detail', () => {
    expect(classifyTlsError('not a code!\n{"x":1}', 'also bad')).toEqual({
      reason: 'mtls+handshake-error',
      detail: 'UNKNOWN',
    });
  });
});

describe('attachTlsClientErrorHandler', () => {
  function fakeServer(): HttpsServer {
    return new EventEmitter() as unknown as HttpsServer;
  }
  const err = Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
  const sock = { authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT', remoteAddress: '10.0.0.9' };

  it('reports a classified rejection with the outcome label', () => {
    const server = fakeServer();
    const seen: TlsRejection[] = [];
    attachTlsClientErrorHandler(server, (r) => seen.push(r));
    server.emit('tlsClientError', err, sock);
    expect(seen).toEqual([
      {
        reason: 'mtls+rejected_ca',
        outcome: 'rejected_ca',
        detail: 'DEPTH_ZERO_SELF_SIGNED_CERT',
        remoteAddress: '10.0.0.9',
      },
    ]);
  });

  it('swallows exceptions thrown by the sink', () => {
    const server = fakeServer();
    attachTlsClientErrorHandler(server, () => {
      throw new Error('sink is broken');
    });
    expect(() => server.emit('tlsClientError', err, sock)).not.toThrow();
  });
});
