import { HttpException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { DownstreamClient } from './downstream.client';

export interface OrderRequest {
  readonly sku: string;
  readonly quantity: number;
  readonly amount: number;
}

export interface OrderResponse {
  readonly order_id: string;
  readonly inventory: unknown;
  readonly payment: unknown;
}

/**
 * Orchestrates one order: reserve in inventory, then charge via payments.
 *
 * TODO: compensating transaction. If reserve succeeds and charge fails, the
 * reservation is left in place. For demos, the inventory service is in-memory
 * and resets with the process; in a real system this would need a release call.
 */
@Injectable()
export class OrdersService {
  constructor(private readonly downstream: DownstreamClient) {}

  async placeOrder(token: string, body: OrderRequest): Promise<OrderResponse> {
    const reserve = await this.downstream.reserve(token, {
      sku: body.sku,
      quantity: body.quantity,
    });
    if (reserve.status < 200 || reserve.status >= 300) {
      throw new HttpException((reserve.body ?? { error: 'reserve-failed' }) as object, reserve.status);
    }

    const charge = await this.downstream.charge(token, {
      orderId: randomUUID(),
      amount: body.amount,
    });
    if (charge.status < 200 || charge.status >= 300) {
      throw new HttpException((charge.body ?? { error: 'charge-failed' }) as object, charge.status);
    }

    return { order_id: randomUUID(), inventory: reserve.body, payment: charge.body };
  }
}
