import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeClock } from '../clock/clock';
import { AuditService, FileAuditSink, StreamAuditSink, type AuditSink } from './audit.service';

const clock = () => new FakeClock(Date.UTC(2026, 9, 12, 14, 3, 11, 482));

function setup() {
  const lines: string[] = [];
  const sink: AuditSink = { write: (l) => lines.push(l) };
  const audit = new AuditService({ service: 'orders', clock: clock(), sinks: [sink] });
  const last = () => JSON.parse(lines[lines.length - 1] ?? '{}') as Record<string, unknown>;
  return { audit, lines, last };
}

describe('AuditService', () => {
  it('writes one newline-terminated JSON line per event, with fields in a fixed order', () => {
    const { audit, lines, last } = setup();
    audit.record({
      event: 'access',
      decision: 'deny',
      reason: 'jwt+replayed',
      resource: 'POST /orders',
      peer_identity: 'spiffe://bastion.local/services/edge',
      user_sub: 'alice',
      jwt_jti: 'a'.repeat(32),
      trace_id: 'b'.repeat(16),
      status: 401,
      remote_addr: '10.0.0.5',
      detail: 'x',
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]?.endsWith('\n')).toBe(true);
    expect(Object.keys(last())).toEqual([
      'ts', 'service', 'event', 'decision', 'reason', 'resource', 'peer_identity',
      'user_sub', 'jwt_jti', 'trace_id', 'remote_addr', 'detail', 'status',
    ]);
    expect(last()).toMatchObject({
      ts: '2026-10-12T14:03:11.482Z',
      service: 'orders',
      decision: 'deny',
    });
  });

  it('omits fields that were not given', () => {
    const { audit, last } = setup();
    audit.record({ event: 'access', decision: 'allow', reason: 'ok' });
    expect(Object.keys(last())).toEqual(['ts', 'service', 'event', 'decision', 'reason']);
  });

  it('can never write a token, key or password, even if one is smuggled in', () => {
    const { audit, lines } = setup();
    audit.record({
      event: 'access', decision: 'allow', reason: 'ok',
      token: 'eyJ.SECRET.sig', password: 'hunter2', authorization: 'Bearer x', key: 'K',
    } as never);
    expect(lines[0]).not.toContain('SECRET');
    expect(lines[0]).not.toContain('hunter2');
    expect(lines[0]).not.toContain('Bearer');
  });

  it('neutralises control characters and caps field length', () => {
    const { audit, lines, last } = setup();
    audit.record({ event: 'access', decision: 'deny', reason: `bad\nline\u0000${'x'.repeat(500)}` });
    expect(lines).toHaveLength(1);
    expect(String(last().reason)).toHaveLength(200);
    expect(String(last().reason)).toContain('bad?line?');
  });

  it.each([[99], [600], [401.5], [Number.NaN]])('drops the invalid status %p', (status) => {
    const { audit, last } = setup();
    audit.record({ event: 'access', decision: 'deny', reason: 'r', status });
    expect('status' in last()).toBe(false);
  });

  it('keeps writing to other sinks when one fails, and counts the failure', () => {
    const goodLines: string[] = [];
    const good: AuditSink = { write: (l) => goodLines.push(l) };
    const bad: AuditSink = { write: () => { throw new Error('disk full'); } };
    const errors: unknown[] = [];
    const audit = new AuditService({
      service: 'orders', clock: clock(), sinks: [bad, good], onSinkError: (e) => errors.push(e),
    });
    expect(() => audit.record({ event: 'access', decision: 'allow', reason: 'ok' })).not.toThrow();
    expect(goodLines).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(audit.sinkFailures()).toBe(1);
  });
});

describe('sinks', () => {
  it('FileAuditSink creates its directory and appends one line per event', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'bastion-audit-')), 'nested', 'orders.log');
    const audit = new AuditService({
      service: 'orders', clock: clock(), sinks: [new FileAuditSink(path)],
    });
    audit.record({ event: 'access', decision: 'allow', reason: 'ok' });
    audit.record({ event: 'access', decision: 'deny', reason: 'jwt+bad_sig' });
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1] as string)).toMatchObject({ reason: 'jwt+bad_sig' });
  });

  it('StreamAuditSink writes to the given stream', () => {
    const chunks: string[] = [];
    new StreamAuditSink({ write: (c) => chunks.push(c) }).write('line\n');
    expect(chunks).toEqual(['line\n']);
  });
});
