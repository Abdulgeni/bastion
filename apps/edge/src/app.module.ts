import { Module, type DynamicModule } from '@nestjs/common';
import { BastionModule, type BastionConfig } from '@bastion/common';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { UsersStore } from './auth/users.store';
import { OrdersClient } from './orders/orders.client';
import { OrdersController } from './orders/orders.controller';

/** Edge's Nest module. Built with config because BastionModule is dynamic. */
@Module({})
export class EdgeAppModule {
  static forRoot(config: BastionConfig): DynamicModule {
    return {
      module: EdgeAppModule,
      imports: [BastionModule.forRoot({ config })],
      controllers: [AuthController, OrdersController],
      providers: [AuthService, UsersStore, OrdersClient],
    };
  }
}
