import { createHash, randomBytes, timingSafeEqual } from 'crypto';

export function generateApiKey(prefix = 'PMS_'): { raw: string; prefix: string; hash: string } {
  const random = randomBytes(32).toString('base64url');
  const raw = `${prefix}${random}`;
  const lookup = randomBytes(8).toString('hex');
  const keyPrefix = `${prefix}${lookup}`;
  const hash = hashApiKey(raw);
  return { raw, prefix: keyPrefix, hash };
}

export function hashApiKey(raw: string): string {
  const pepper = process.env.API_KEY_HASH_PEPPER || '';
  return createHash('sha256').update(raw + pepper).digest('hex');
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
