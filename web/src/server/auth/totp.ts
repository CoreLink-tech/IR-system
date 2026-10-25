import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

/** RFC 6238 TOTP (SHA-1, 30s step, 6 digits). */

function base32Encode(buf: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

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

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function otpauthUri(secret: string, accountName: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const q = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${q.toString()}`;
}

function hotp(secretBuf: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secretBuf).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, '0');
}

export function verifyTotp(
  secretBase32: string,
  code: string,
  opts: { window?: number; lastStep?: number | null } = {},
): { ok: boolean; step?: number } {
  const window = opts.window ?? 1;
  const cleaned = (code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(cleaned)) return { ok: false };
  const secretBuf = base32Decode(secretBase32);
  const step = Math.floor(Date.now() / 1000 / 30);
  for (let w = -window; w <= window; w++) {
    const s = step + w;
    if (opts.lastStep != null && s <= opts.lastStep) continue;
    const expected = hotp(secretBuf, s);
    const a = Buffer.from(expected);
    const b = Buffer.from(cleaned);
    if (a.length === b.length && timingSafeEqual(a, b)) {
      return { ok: true, step: s };
    }
  }
  return { ok: false };
}

export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(8).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`);
  }
  return codes;
}
