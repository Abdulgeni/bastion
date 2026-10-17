import { bootstrapService, loadConfig } from '@bastion/common';
import { PaymentsAppModule } from './app.module';

async function main(): Promise<void> {
  const config = loadConfig();
  await bootstrapService({ config, appModule: PaymentsAppModule.forRoot(config) });
}

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`payments: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
