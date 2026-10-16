import type { RandomSource } from '../random/random-source';

export const TRACE_HEADER = 'x-bastion-trace-id';
const TRACE_ID = /^[0-9a-f]{16}$/;

export function resolveTraceId(
  header: string | readonly string[] | undefined,
  random: RandomSource,
): string {
  const value = Array.isArray(header) ? header[0] : header;
  return typeof value === 'string' && TRACE_ID.test(value) ? value : random.bytes(8).toString('hex');
}
