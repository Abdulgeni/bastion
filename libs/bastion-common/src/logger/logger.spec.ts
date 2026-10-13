import { FakeClock } from '../clock/clock';
import { createLogger } from './logger';

function capture(level = 'info') {
  const lines: string[] = [];
  const clock = new FakeClock(Date.UTC(2026, 9, 12, 14, 3, 11, 482));
  const log = createLogger({
    service: 'orders',
    level,
    clock,
    destination: { write: (msg: string) => void lines.push(msg) },
  });
  return { log, lines, parse: (i = 0) => JSON.parse(lines[i] ?? '{}') as Record<string, unknown> };
}

describe('createLogger', () => {
  it('emits ts from the Clock, level label, and service', () => {
    const { log, parse } = capture();
    log.info('hello');
    expect(parse()).toMatchObject({
      ts: '2026-10-12T14:03:11.482Z',
      level: 'info',
      service: 'orders',
      msg: 'hello',
    });
  });

  it('redacts tokens, passwords, keys and certs', () => {
    const { log, parse } = capture();
    log.info(
      { token: 'abc', headers: { authorization: 'Bearer x' }, user: { password: 'p' }, cert: 'PEM' },
      'sensitive',
    );
    const rec = parse();
    expect(rec.token).toBe('[REDACTED]');
    expect(rec.cert).toBe('[REDACTED]');
    expect((rec.headers as Record<string, unknown>).authorization).toBe('[REDACTED]');
    expect((rec.user as Record<string, unknown>).password).toBe('[REDACTED]');
  });

  it('keeps non-sensitive fields', () => {
    const { log, parse } = capture();
    log.info({ jti: 'b2c1', resource: 'POST /orders' }, 'ok');
    expect(parse()).toMatchObject({ jti: 'b2c1', resource: 'POST /orders' });
  });

  it('respects the configured level', () => {
    const { log, lines } = capture('info');
    log.debug('dropped');
    expect(lines).toHaveLength(0);
  });
});
