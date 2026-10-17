import {
  Body,
  Controller,
  Headers,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  AllowCallers,
  JwtAuthGuard,
  PeerIdentityGuard,
  RequireScope,
  extractBearerToken,
} from '@bastion/common';
import { OrdersService, type OrderRequest } from './orders.service';

/**
 * POST /orders: only edge may call. Requires a valid edge-signed JWT with
 * `orders:write`. PeerIdentityGuard runs first (mTLS identity check), then
 * JwtAuthGuard (signature, claims, expiry, audience, replay).
 */
@Controller('orders')
@AllowCallers('edge')
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Post()
  @RequireScope('orders:write')
  @UseGuards(PeerIdentityGuard, JwtAuthGuard)
  async create(
    @Headers('authorization') auth: string | undefined,
    @Body() body: OrderRequest,
  ): Promise<unknown> {
    const token = extractBearerToken(auth);
    if (token === undefined) throw new UnauthorizedException();
    return this.orders.placeOrder(token, body);
  }
}
