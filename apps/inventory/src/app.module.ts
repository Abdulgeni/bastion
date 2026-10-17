import { Module, type DynamicModule } from '@nestjs/common';
import { BastionModule, type BastionConfig } from '@bastion/common';
import { StockController } from './stock/stock.controller';
import { StockService } from './stock/stock.service';

@Module({})
export class InventoryAppModule {
  static forRoot(config: BastionConfig): DynamicModule {
    return {
      module: InventoryAppModule,
      imports: [BastionModule.forRoot({ config })],
      controllers: [StockController],
      providers: [StockService],
    };
  }
}
