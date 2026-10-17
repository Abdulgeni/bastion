import { BadRequestException, Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AllowCallers, JwtAuthGuard, PeerIdentityGuard, RequireScope } from '@bastion/common';
import { ChargeService, type ChargeRequest } from './charge.service';

/** POST /charge: only orders may call, requires `payments:charge` scope. */
@Controller('charge')
@AllowCallers('orders')
export class ChargeController {
  constructor(private readonly charge: ChargeService) {}

  @Post()
  @RequireScope('payments:charge')
  @UseGuards(PeerIdentityGuard, JwtAuthGuard)
  process(@Body() body: ChargeRequest): unknown {
    try {
      return this.charge.charge(body);
    } catch {
      throw new BadRequestException({ error: 'invalid-body' });
    }
  }
}
