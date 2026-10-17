import { Injectable } from '@nestjs/common';
import { createHash, createHmac } from 'node:crypto';

export interface ChargeRequest {
  readonly orderId: string;
  readonly amount: number;
}

export interface ChargeResponse {
  readonly charged: true;
  readonly amount: number;
  readonly keyFingerprint: string;
  readonly receipt: string;
}

/**
 * Charges by HMACing the order receipt with the in-memory API key.
 *
 * TODO Vault step: replace the stub key with one minted by Vault and rotated
 * every VAULT_KEY_TTL_SECONDS. Until then, the key is a fixed string per
 * process, and the fingerprint is its first 16 hex characters so a demo can
 * observe rotation once Vault is wired.
 */
@Injectable()
export class ChargeService {
  private readonly apiKey = 'stub-api-key';
  private readonly keyFingerprint = createHash('sha256')
    .update(this.apiKey)
    .digest('hex')
    .slice(0, 16);

  charge(body: ChargeRequest): ChargeResponse {
    if (typeof body.orderId !== 'string' || typeof body.amount !== 'number') {
      throw new Error('invalid-body');
    }
    const receipt = createHmac('sha256', this.apiKey).update(body.orderId).digest('hex');
    return {
      charged: true,
      amount: body.amount,
      keyFingerprint: this.keyFingerprint,
      receipt,
    };
  }
}
