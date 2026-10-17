import { fetch as undiciFetch, type Dispatcher } from 'undici';

export interface CallJsonOptions {
  readonly url: string;
  readonly method?: 'GET' | 'POST';
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
  /** The undici Agent (usually from `createMtlsAgent`) carrying our client cert. */
  readonly dispatcher?: Dispatcher;
  readonly timeoutMs?: number;
}

export interface CallJsonResult<T = unknown> {
  readonly status: number;
  readonly body: T | undefined;
}

/**
 * One JSON call to a downstream service. Uses undici's fetch so an mTLS Agent
 * can be passed as `dispatcher`. Bounded time; no redirects. The caller decides
 * what a non-2xx status means.
 */
export async function callJson<T = unknown>(
  opts: CallJsonOptions,
): Promise<CallJsonResult<T>> {
  const res = await undiciFetch(opts.url, {
    method: opts.method ?? 'POST',
    headers: {
      accept: 'application/json',
      ...(opts.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...opts.headers,
    },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    dispatcher: opts.dispatcher,
    signal: AbortSignal.timeout(opts.timeoutMs ?? 5_000),
    redirect: 'error',
  });
  const text = await res.text();
  const body = text.length > 0 ? (JSON.parse(text) as T) : undefined;
  return { status: res.status, body };
}
