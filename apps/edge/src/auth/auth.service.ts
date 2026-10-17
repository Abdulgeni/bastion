import { Injectable } from '@nestjs/common';
import { AccessRecorder, AuditService, MetricsService, TokenIssuer } from '@bastion/common';
import { UsersStore } from './users.store';

/** Authenticates a demo user and mints a 5-minute JWT. */
@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersStore,
    private readonly issuer: TokenIssuer,
    private readonly recorder: AccessRecorder,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  /** Returns the signed token, or undefined if the credentials are wrong. */
  async login(username: string, password: string): Promise<string | undefined> {
    const user = this.users.find(username);
    if (!user || user.password !== password) {
      this.metrics.recordAuthz('deny', 'POST /login');
      this.audit.record({
        event: 'login',
        decision: 'deny',
        reason: 'login+bad-credentials',
        resource: 'POST /login',
        status: 401,
      });
      return undefined;
    }
    const { token } = await this.issuer.issue({
      subject: user.sub,
      audience: ['orders', 'inventory', 'payments'],
      scope: ['orders:write', 'inventory:reserve', 'payments:charge'],
    });
    this.metrics.recordAuthz('allow', 'POST /login');
    this.audit.record({
      event: 'login',
      decision: 'allow',
      reason: 'ok',
      resource: 'POST /login',
      user_sub: user.sub,
    });
    return token;
  }
}
