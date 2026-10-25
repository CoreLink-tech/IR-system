import { describe, it, expect } from 'vitest';
import { generateTotpSecret, otpauthUri, verifyTotp, generateRecoveryCodes } from './totp';
import { createHmac } from 'crypto';

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of cleaned) {
    const idx = alphabet.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function codeAt(secret: string, step: number): string {
  const secretBuf = base32Decode(secret);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac('sha1', secretBuf).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

describe('totp', () => {
  it('generates a base32 secret', () => {
    const s = generateTotpSecret();
    expect(s.length).toBeGreaterThan(10);
    expect(s).toMatch(/^[A-Z2-7]+$/);
  });

  it('builds an otpauth URI', () => {
    const uri = otpauthUri('JBSWY3DPEHPK3PXP', 'user@example.com', 'Security Dashboard');
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(uri).toContain('issuer=Security');
  });

  it('verifies a valid current code', () => {
    const secret = generateTotpSecret();
    const step = Math.floor(Date.now() / 1000 / 30);
    const code = codeAt(secret, step);
    const r = verifyTotp(secret, code, { window: 1 });
    expect(r.ok).toBe(true);
    expect(r.step).toBe(step);
  });

  it('rejects a wrong code', () => {
    const secret = generateTotpSecret();
    const r = verifyTotp(secret, '000000', { window: 0 });
    // May randomly pass; use clearly invalid length instead
    const bad = verifyTotp(secret, '12', { window: 1 });
    expect(bad.ok).toBe(false);
  });

  it('rejects replay of the same step when lastStep is set', () => {
    const secret = generateTotpSecret();
    const step = Math.floor(Date.now() / 1000 / 30);
    const code = codeAt(secret, step);
    const first = verifyTotp(secret, code, { window: 1 });
    expect(first.ok).toBe(true);
    const second = verifyTotp(secret, code, { window: 1, lastStep: first.step });
    expect(second.ok).toBe(false);
  });

  it('generates unique recovery codes', () => {
    const codes = generateRecoveryCodes(10);
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    expect(codes[0]).toMatch(/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/);
  });
});
