import {
  BadRequestException,
  Body,
  Controller,
  Post,
  ServiceUnavailableException,
  UseGuards,
} from '@nestjs/common';
import { AllowCallers, JwtAuthGuard, PeerIdentityGuard, RequireScope } from '@bastion/common';
import { ChargeService, type ChargeRequest } from './charge.service';
import { VAULT_UNAVAILABLE_MESSAGE } from '../vault/key-holder';

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
    } catch (err) {
      if (err instanceof Error && err.message === VAULT_UNAVAILABLE_MESSAGE) {
        throw new ServiceUnavailableException({ error: 'vault-unavailable' });
      }
      throw new BadRequestException({ error: 'invalid-body' });
    }
  }
}
