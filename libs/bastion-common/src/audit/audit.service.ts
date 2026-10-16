import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Clock } from '../clock/clock';

export type AuditEventType = 'access' | 'handshake' | 'login' | 'vault';
export type AuditDecision = 'allow' | 'deny';

export interface AuditEvent {
  readonly event: AuditEventType;
  readonly decision: AuditDecision;
  readonly reason: string;
  readonly resource?: string;
  readonly peer_identity?: string;
  readonly user_sub?: string;
  readonly jwt_jti?: string;
  readonly trace_id?: string;
  readonly status?: number;
  readonly remote_addr?: string;
  readonly detail?: string;
}

export interface AuditSink {
  write(line: string): void;
}

export class StreamAuditSink implements AuditSink {
  constructor(private readonly stream: { write(chunk: string): unknown } = process.stdout) {}
  write(line: string): void {
    this.stream.write(line);
  }
}

export class FileAuditSink implements AuditSink {
  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }
  write(line: string): void {
    appendFileSync(this.path, line, { mode: 0o640 });
  }
}

const MAX_FIELD = 200;
// eslint-disable-next-line no-control-regex -- the control chars are the ones we strip
const CONTROL = /[\u0000-\u001f\u007f]/g;
const STRING_FIELDS = [
  'reason', 'resource', 'peer_identity', 'user_sub', 'jwt_jti', 'trace_id', 'remote_addr', 'detail',
] as const;

function clean(value: string): string {
  return value.replace(CONTROL, '?').slice(0, MAX_FIELD);
}

export interface AuditServiceOptions {
  readonly service: string;
  readonly clock: Clock;
  readonly sinks: readonly AuditSink[];
  readonly onSinkError?: (err: unknown) => void;
}

export class AuditService {
  private failures = 0;
  constructor(private readonly opts: AuditServiceOptions) {}

  sinkFailures(): number {
    return this.failures;
  }

  record(event: AuditEvent): void {
    const line = `${JSON.stringify(this.build(event))}\n`;
    for (const sink of this.opts.sinks) {
      try {
        sink.write(line);
      } catch (err) {
        this.failures += 1;
        this.reportFailure(err);
      }
    }
  }

  private build(event: AuditEvent): Record<string, unknown> {
    const record: Record<string, unknown> = {
      ts: this.opts.clock.now().toISOString(),
      service: this.opts.service,
      event: event.event,
      decision: event.decision,
    };
    for (const key of STRING_FIELDS) {
      const value = event[key];
      if (typeof value === 'string') record[key] = clean(value);
    }
    const { status } = event;
    if (typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599) {
      record.status = status;
    }
    return record;
  }

  private reportFailure(err: unknown): void {
    if (this.opts.onSinkError) {
      this.opts.onSinkError(err);
      return;
    }
    process.stderr.write('audit sink failed: some audit events may be missing\n');
  }
}
