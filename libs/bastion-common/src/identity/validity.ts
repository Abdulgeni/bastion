export type WindowState = 'valid' | 'outside' | 'unparseable';

/**
 * Compares `nowMs` with a certificate's validity window, given as the date
 * strings Node exposes (e.g. "Oct 12 00:45:42 2026 GMT"). Unparseable dates fail closed.
 */
export function certWindowState(
  nowMs: number,
  validFrom: string | undefined,
  validTo: string | undefined,
): WindowState {
  const from = Date.parse(validFrom ?? '');
  const to = Date.parse(validTo ?? '');
  if (!Number.isFinite(from) || !Number.isFinite(to)) return 'unparseable';
  return nowMs >= from && nowMs <= to ? 'valid' : 'outside';
}
