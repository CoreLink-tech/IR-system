import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

/** RFC 4648 base32, the encoding authenticator apps expect for the shared secret. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0; let value = 0; let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0; let value = 0; const out: number[] = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('not base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

export const TOTP_PERIOD = 30;
export const TOTP_DIGITS = 6;

/** A new random 160-bit secret, base32 encoded (what the person types or scans into their authenticator). */
export function newTotpSecret(): string { return base32Encode(randomBytes(20)); }

/** RFC 4226 HMAC-based one-time password for one counter value. */
export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', secret).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 10 ** digits).padStart(digits, '0');
}

export const timeStep = (now: Date, period = TOTP_PERIOD) => Math.floor(now.getTime() / 1000 / period);
export const totp = (secretBase32: string, now: Date, digits = TOTP_DIGITS) => hotp(base32Decode(secretBase32), timeStep(now), digits);

const sameCode = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export interface TotpCheck { ok: boolean; /** The time step the code belongs to (store it to refuse a second use). */ step?: number; reason?: 'format' | 'wrong' | 'replay' }

/**
 * Checks a code. `window` steps either side are accepted (1 = 30 seconds before or after, for clocks that are
 * a little off). A code from a step at or before `lastStep` is refused, so one code cannot be used twice, even
 * inside its window.
 */
export function verifyTotp(secretBase32: string, code: string, now: Date, opts: { window?: number; lastStep?: number | null } = {}): TotpCheck {
  const c = String(code ?? '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return { ok: false, reason: 'format' };
  const secret = base32Decode(secretBase32);
  const window = opts.window ?? 1;
  const current = timeStep(now);
  let matched: number | undefined;
  for (let d = -window; d <= window; d++) {          // check every step, not stopping at the first, so timing does not reveal which
    const step = current + d;
    if (sameCode(hotp(secret, step), c) && matched === undefined) matched = step;
  }
  if (matched === undefined) return { ok: false, reason: 'wrong' };
  if (opts.lastStep !== null && opts.lastStep !== undefined && matched <= opts.lastStep) return { ok: false, step: matched, reason: 'replay' };
  return { ok: true, step: matched };
}

/** The otpauth:// address an authenticator app reads from a QR code. */
export function otpauthUri(secretBase32: string, accountName: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
}
