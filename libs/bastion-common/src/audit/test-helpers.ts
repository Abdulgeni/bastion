import { FakeClock } from '../clock/clock';
import { MetricsService } from '../metrics/metrics.service';
import { AccessRecorder } from './access-recorder';
import { AuditService, type AuditSink } from './audit.service';

/** An audit sink that keeps lines in memory. */
export class MemorySink implements AuditSink {
  readonly lines: string[] = [];

  write(line: string): void {
    this.lines.push(line);
  }
}

/** Audit + metrics + recorder wired to in-memory sinks, for tests. */
export function makeObservability(
  service = 'orders',
  clock = new FakeClock(Date.UTC(2026, 9, 12, 12, 0, 0)),
) {
  const sink = new MemorySink();
  const audit = new AuditService({ service, clock, sinks: [sink] });
  const metrics = new MetricsService(service, clock);
  const recorder = new AccessRecorder(audit, metrics);
  return {
    clock,
    audit,
    metrics,
    recorder,
    /** Parsed audit events written so far. */
    events: () => sink.lines.map((l) => JSON.parse(l) as Record<string, unknown>),
    rawLines: () => sink.lines,
    /** The value of one metric sample, matching labels in any order. */
    async sample(name: string, labels: Record<string, string> = {}): Promise<number | undefined> {
      return parseSample((await metrics.render()).body, name, labels);
    },
  };
}

/** Finds `name{labels...} value` in Prometheus text, ignoring label order. */
export function parseSample(
  text: string,
  name: string,
  labels: Record<string, string>,
): number | undefined {
  for (const line of text.split('\n')) {
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})? (\S+)$/.exec(line);
    if (!m || m[1] !== name) continue;
    const got = Object.fromEntries(
      [...(m[2] ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((x) => [x[1], x[2]]),
    );
    if (Object.entries(labels).every(([k, v]) => got[k] === v)) return Number(m[3]);
  }
  return undefined;
}
