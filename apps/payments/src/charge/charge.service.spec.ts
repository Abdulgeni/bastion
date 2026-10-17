import { ChargeService } from './charge.service';
import { KeyHolder, VAULT_UNAVAILABLE_MESSAGE } from '../vault/key-holder';

/** Minimal KeyHolder stub that returns a fixed key. */
class FakeHolder {
  constructor(private readonly bytes: Buffer) {}
  currentKey(): Buffer {
    return this.bytes;
  }
}

describe('ChargeService (with Vault-derived key)', () => {
  it('HMACs the receipt with the current key and returns a 16-hex fingerprint', () => {
    const key = Buffer.alloc(32, 0xab);
    const service = new ChargeService(new FakeHolder(key) as unknown as KeyHolder);
    const r = service.charge({ orderId: 'abc', amount: 100 });
    expect(r.charged).toBe(true);
    expect(r.amount).toBe(100);
    expect(r.receipt).toMatch(/^[0-9a-f]{64}$/);
    expect(r.keyFingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces a different fingerprint when the key rotates', () => {
    const a = new ChargeService(new FakeHolder(Buffer.alloc(32, 0x01)) as unknown as KeyHolder);
    const b = new ChargeService(new FakeHolder(Buffer.alloc(32, 0x02)) as unknown as KeyHolder);
    const ra = a.charge({ orderId: 'abc', amount: 100 });
    const rb = b.charge({ orderId: 'abc', amount: 100 });
    expect(ra.keyFingerprint).not.toBe(rb.keyFingerprint);
    expect(ra.receipt).not.toBe(rb.receipt);
  });

  it('rejects malformed bodies', () => {
    const service = new ChargeService(new FakeHolder(Buffer.alloc(32, 0x00)) as unknown as KeyHolder);
    expect(() => service.charge({ orderId: 123 as never, amount: 100 })).toThrow(/invalid-body/);
    expect(() => service.charge({ orderId: 'x', amount: 'y' as never })).toThrow(/invalid-body/);
  });

  it('propagates a fail-closed key error from the holder', () => {
    const failingHolder = {
      currentKey: () => {
        throw new Error(VAULT_UNAVAILABLE_MESSAGE);
      },
    };
    const service = new ChargeService(failingHolder as unknown as KeyHolder);
    expect(() => service.charge({ orderId: 'abc', amount: 100 })).toThrow(VAULT_UNAVAILABLE_MESSAGE);
  });
});
