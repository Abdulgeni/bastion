import { createHash, randomBytes } from 'node:crypto';
import { ConfigError } from '../errors';

/** Where Bastion gets randomness (jti, serials, nonces). Never use Math.random. */
export interface RandomSource {
  /** Returns exactly `length` random bytes. */
  bytes(length: number): Buffer;
}

const MAX_BYTES = 65_536;

function assertLength(length: number): void {
  if (!Number.isInteger(length) || length < 1 || length > MAX_BYTES) {
    throw new RangeError(`length must be an integer between 1 and ${MAX_BYTES}`);
  }
}

/** Production source: the OS CSPRNG. */
export class CsprngRandom implements RandomSource {
  bytes(length: number): Buffer {
    assertLength(length);
    return randomBytes(length);
  }
}

/**
 * Deterministic source for tests: SHA-256(seed || counter) blocks.
 * Same seed gives the same byte stream. NOT secure; test mode only.
 */
export class SeededRandom implements RandomSource {
  private counter = 0n;

  constructor(private readonly seed: string) {}

  bytes(length: number): Buffer {
    assertLength(length);
    const blocks: Buffer[] = [];
    let have = 0;
    while (have < length) {
      blocks.push(this.nextBlock());
      have += 32;
    }
    return Buffer.concat(blocks).subarray(0, length);
  }

  private nextBlock(): Buffer {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(this.counter);
    this.counter += 1n;
    return createHash('sha256').update('bastion-seeded-random:').update(this.seed).update(counter).digest();
  }
}

/** Fails loudly if a test seed is present in production. */
export function assertSeedAllowed(nodeEnv: string | undefined, seed: string | undefined): void {
  if (seed !== undefined && nodeEnv === 'production') {
    throw new ConfigError(['BASTION_TEST_SEED must not be set when NODE_ENV=production']);
  }
}

export interface RandomSourceOptions {
  readonly nodeEnv: string | undefined;
  readonly seed?: string;
}

/** CSPRNG unless a test seed is given (and allowed). */
export function createRandomSource(opts: RandomSourceOptions): RandomSource {
  assertSeedAllowed(opts.nodeEnv, opts.seed);
  return opts.seed === undefined ? new CsprngRandom() : new SeededRandom(opts.seed);
}
