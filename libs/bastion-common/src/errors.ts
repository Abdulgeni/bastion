/**
 * Base error for configuration and environment problems. Messages never echo
 * values; only field names and file paths.
 */
export class ConfigError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`Invalid configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}
