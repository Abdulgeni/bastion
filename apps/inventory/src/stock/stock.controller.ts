import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AllowCallers, JwtAuthGuard, PeerIdentityGuard, RequireScope } from '@bastion/common';
import { StockService, type ReserveRequest } from './stock.service';

/** POST /reserve: only orders may call, requires `inventory:reserve` scope. */
@Controller('reserve')
@AllowCallers('orders')
export class StockController {
  constructor(private readonly stock: StockService) {}

  @Post()
  @RequireScope('inventory:reserve')
  @UseGuards(PeerIdentityGuard, JwtAuthGuard)
  reserve(@Body() body: ReserveRequest): unknown {
    return this.stock.reserve(body);
  }
}
