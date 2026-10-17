import {
  Body,
  Controller,
  Headers,
  HttpException,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard, RequireScope, extractBearerToken } from '@bastion/common';
import { OrdersClient } from './orders.client';

/**
 * POST /orders: verify the user's JWT here, then forward to orders over mTLS
 * with the same token. No PeerIdentityGuard: the host has no client cert; only
 * the JWT authenticates the user at this hop.
 */
@Controller('orders')
export class OrdersController {
  constructor(private readonly client: OrdersClient) {}

  @Post()
  @RequireScope('orders:write')
  @UseGuards(JwtAuthGuard)
  async create(
    @Headers('authorization') auth: string | undefined,
    @Body() body: unknown,
  ): Promise<unknown> {
    const token = extractBearerToken(auth);
    if (token === undefined) throw new UnauthorizedException();
    const result = await this.client.createOrder(token, body);
    if (result.status >= 200 && result.status < 300) return result.body;
    throw new HttpException((result.body ?? { error: 'downstream' }) as object, result.status);
  }
}
