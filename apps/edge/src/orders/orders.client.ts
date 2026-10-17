import { Inject, Injectable } from '@nestjs/common';
import {
  BASTION_CONFIG,
  callJson,
  createMtlsAgent,
  readTlsMaterial,
  spiffeIdFor,
  type BastionConfig,
  type CallJsonResult,
} from '@bastion/common';
import type { Agent } from 'undici';

/** Calls orders over mTLS, presenting edge's client certificate. */
@Injectable()
export class OrdersClient {
  private readonly agent: Agent;
  private readonly url: string;

  constructor(@Inject(BASTION_CONFIG) config: BastionConfig) {
    const material = readTlsMaterial(config.tls);
    const expectedServerId = spiffeIdFor(config.trustDomain, 'orders');
    this.agent = createMtlsAgent({ material, expectedServerId });
    this.url = `${config.serviceUrls.orders}/orders`;
  }

  async createOrder(token: string, body: unknown): Promise<CallJsonResult> {
    return callJson({
      url: this.url,
      method: 'POST',
      body,
      headers: { authorization: `Bearer ${token}` },
      dispatcher: this.agent,
    });
  }
}
