import { FakeClock } from '../../../../libs/bastion-common/src/clock/clock';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyHolder, VAULT_UNAVAILABLE_MESSAGE } from './key-holder';
import { VaultUnavailableError, type VaultClient } from './vault.client';

const NOW = Date.UTC(2026, 9, 12, 12, 0, 0);
const TTL_MS = 10_000;

class FakeVault implements Pick<VaultClient, 'login' | 'randomBytes'> {
  calls = 0;
  fail = false;
  constructor(private readonly responses: readonly Buffer[]) {}
  async login(): Promise<{ token: string; leaseDurationSeconds: number }> {
    return { token: 'tok', leaseDurationSeconds: 3_600 };
  }
  async unwrapSecretId(): Promise<string> {
    return 'unwrapped-' + this.calls;
  }
  async randomBytes(): Promise<Buffer> {
    if (this.fail) throw new VaultUnavailableError('boom');
    const r = this.responses[this.calls % this.responses.length];
    this.calls += 1;
    return r ?? Buffer.alloc(32, 0);
  }
}

// Each test uses a tmpdir for BASTION_VAR_DIR with no root-token file,
// so readRootTokenIfPresent returns undefined and the AppRole+unwrap path
// (which the fake implements) is exercised.
function setup(
  opts: {
    fail?: boolean;
    responses?: readonly Buffer[];
    manualTimer?: (fn: () => void, ms: number) => ReturnType<typeof setInterval>;
  } = {},
) {
  const clock = new FakeClock(NOW);
  const emptyDir = mkdtempSync(join(tmpdir(), 'bastion-kh-'));
  process.env.BASTION_VAR_DIR = emptyDir;
  const vault = new FakeVault(opts.responses ?? [Buffer.alloc(32, 0xaa)]);
  vault.fail = opts.fail === true;
  const registrations: Array<() => number | undefined> = [];
  const metrics = { registerVaultKeyAge: (fn: () => number | undefined) => registrations.push(fn) };
  const holder = new KeyHolder(
    {
      vault: vault as unknown as VaultClient,
      clock,
      metrics,
      ttlMs: TTL_MS,
      roleId: 'rid',
      secretId: 'wsid',
    },
    opts.manualTimer,
  );
  return { holder, clock, vault, registrations };
}

describe('KeyHolder', () => {
  it('starts by fetching a key and registering the age metric', async () => {
    const s = setup();
    await s.holder.start();
    expect(s.holder.currentKey()).toEqual(Buffer.alloc(32, 0xaa));
    expect(s.holder.issuedAt()).toBe(NOW);
    expect(s.registrations).toHaveLength(1);
    s.holder.stop();
  });

  it('rotates the key when the timer fires', async () => {
    let captured: (() => void) | undefined;
    const s = setup({
      responses: [Buffer.alloc(32, 0x01), Buffer.alloc(32, 0x02)],
      manualTimer: (fn) => {
        captured = fn;
        return { unref: () => undefined } as unknown as ReturnType<typeof setInterval>;
      },
    });
    await s.holder.start();
    expect(s.holder.currentKey()).toEqual(Buffer.alloc(32, 0x01));
    captured?.();
    await new Promise((r) => setImmediate(r));
    expect(s.holder.currentKey()).toEqual(Buffer.alloc(32, 0x02));
    s.holder.stop();
  });

  it('fails closed when the current key is too old', async () => {
    const s = setup();
    await s.holder.start();
    s.clock.advanceMs(TTL_MS * 2 + 1);
    expect(() => s.holder.currentKey()).toThrow(VAULT_UNAVAILABLE_MESSAGE);
    s.holder.stop();
  });

  it('throws at start when the first fetch fails', async () => {
    const s = setup({ fail: true });
    await expect(s.holder.start()).rejects.toThrow(VaultUnavailableError);
  });

  it('keeps serving the last key through a transient refresh failure within the age window', async () => {
    let captured: (() => void) | undefined;
    const s = setup({
      responses: [Buffer.alloc(32, 0x33)],
      manualTimer: (fn) => {
        captured = fn;
        return { unref: () => undefined } as unknown as ReturnType<typeof setInterval>;
      },
    });
    await s.holder.start();
    s.vault.fail = true;
    s.clock.advanceMs(TTL_MS);
    captured?.();
    await new Promise((r) => setImmediate(r));
    expect(s.holder.currentKey()).toEqual(Buffer.alloc(32, 0x33));
    s.holder.stop();
  });
});
