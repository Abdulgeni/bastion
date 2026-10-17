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

/** mTLS clients for orders' two downstream services (inventory, payments). */
@Injectable()
export class DownstreamClient {
  private readonly inventoryAgent: Agent;
  private readonly paymentsAgent: Agent;
  private readonly inventoryUrl: string;
  private readonly paymentsUrl: string;

  constructor(@Inject(BASTION_CONFIG) config: BastionConfig) {
    const material = readTlsMaterial(config.tls);
    this.inventoryAgent = createMtlsAgent({
      material,
      expectedServerId: spiffeIdFor(config.trustDomain, 'inventory'),
    });
    this.paymentsAgent = createMtlsAgent({
      material,
      expectedServerId: spiffeIdFor(config.trustDomain, 'payments'),
    });
    this.inventoryUrl = `${config.serviceUrls.inventory}/reserve`;
    this.paymentsUrl = `${config.serviceUrls.payments}/charge`;
  }

  reserve(token: string, body: unknown): Promise<CallJsonResult> {
    return callJson({
      url: this.inventoryUrl,
      body,
      headers: { authorization: `Bearer ${token}` },
      dispatcher: this.inventoryAgent,
    });
  }

  charge(token: string, body: unknown): Promise<CallJsonResult> {
    return callJson({
      url: this.paymentsUrl,
      body,
      headers: { authorization: `Bearer ${token}` },
      dispatcher: this.paymentsAgent,
    });
  }
}
