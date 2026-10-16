export interface ResourceRequest {
  readonly method?: string;
  readonly url?: string;
  readonly route?: { readonly path?: unknown };
}

export function describeResource(req: ResourceRequest): string {
  const path = typeof req.route?.path === 'string' ? req.route.path : (req.url ?? '').split('?')[0];
  return `${req.method ?? 'UNKNOWN'} ${path}`.slice(0, 200);
}

const LABEL = /^[A-Z]+ \/[A-Za-z0-9/_:.-]{0,80}$/;

export function resourceLabel(resource: string): string {
  return LABEL.test(resource) ? resource : 'other';
}
