import { Injectable } from '@nestjs/common';
import { createHash, createHmac } from 'node:crypto';
import { KeyHolder } from '../vault/key-holder';

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
 * Charges by HMACing the order receipt with the current Vault-derived key.
 * The key lives only in memory (see KeyHolder). The fingerprint is its first
 * 16 hex SHA-256 characters, so a demo can observe rotation without exposing
 * the key material.
 */
@Injectable()
export class ChargeService {
  constructor(private readonly keys: KeyHolder) {}

  charge(body: ChargeRequest): ChargeResponse {
    if (typeof body.orderId !== 'string' || typeof body.amount !== 'number') {
      throw new Error('invalid-body');
    }
    const key = this.keys.currentKey();
    const receipt = createHmac('sha256', key).update(body.orderId).digest('hex');
    const fingerprint = createHash('sha256').update(key).digest('hex').slice(0, 16);
    return { charged: true, amount: body.amount, keyFingerprint: fingerprint, receipt };
  }
}
