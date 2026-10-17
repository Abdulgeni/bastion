import { ConflictException, Injectable } from '@nestjs/common';

export interface ReserveRequest {
  readonly sku: string;
  readonly quantity: number;
}

export interface ReserveResponse {
  readonly reserved: true;
  readonly sku: string;
  readonly quantity: number;
  readonly remaining: number;
}

/** In-memory stock ledger. Resets with the process; no persistence. */
@Injectable()
export class StockService {
  private readonly stock = new Map<string, number>([['sku-1', 100]]);

  reserve(body: ReserveRequest): ReserveResponse {
    if (typeof body.sku !== 'string' || typeof body.quantity !== 'number') {
      throw new ConflictException({ error: 'invalid-body' });
    }
    if (!Number.isInteger(body.quantity) || body.quantity < 1) {
      throw new ConflictException({ error: 'invalid-quantity' });
    }
    const available = this.stock.get(body.sku) ?? 0;
    if (available < body.quantity) {
      throw new ConflictException({ error: 'out-of-stock', sku: body.sku, available });
    }
    const remaining = available - body.quantity;
    this.stock.set(body.sku, remaining);
    return { reserved: true, sku: body.sku, quantity: body.quantity, remaining };
  }
}
