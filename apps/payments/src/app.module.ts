import { Module, type DynamicModule } from '@nestjs/common';
import { BastionModule, type BastionConfig } from '@bastion/common';
import { ChargeController } from './charge/charge.controller';
import { ChargeService } from './charge/charge.service';

@Module({})
export class PaymentsAppModule {
  static forRoot(config: BastionConfig): DynamicModule {
    return {
      module: PaymentsAppModule,
      imports: [BastionModule.forRoot({ config })],
      controllers: [ChargeController],
      providers: [ChargeService],
    };
  }
}
