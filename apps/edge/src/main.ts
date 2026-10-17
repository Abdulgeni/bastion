import { bootstrapService, loadConfig } from '@bastion/common';
import { EdgeAppModule } from './app.module';

async function main(): Promise<void> {
  const config = loadConfig();
  await bootstrapService({ config, appModule: EdgeAppModule.forRoot(config) });
}

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`edge: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
