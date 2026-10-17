import { Module, type DynamicModule } from '@nestjs/common';
import { BastionModule, type BastionConfig } from '@bastion/common';
import { DownstreamClient } from './orders/downstream.client';
import { OrdersController } from './orders/orders.controller';
import { OrdersService } from './orders/orders.service';

@Module({})
export class OrdersAppModule {
  static forRoot(config: BastionConfig): DynamicModule {
    return {
      module: OrdersAppModule,
      imports: [BastionModule.forRoot({ config })],
      controllers: [OrdersController],
      providers: [OrdersService, DownstreamClient],
    };
  }
}
