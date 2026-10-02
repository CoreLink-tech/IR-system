import { createHash, randomBytes, timingSafeEqual } from 'crypto';

export function generateApiKey(prefix = 'PMS_'): { raw: string; prefix: string; hash: string } {
  // The lookup prefix MUST be the leading part of the raw key, because
  // verifyApiKey() derives it by slicing the presented key.
  const lookup = randomBytes(8).toString('hex'); // 16 chars
  const secret = randomBytes(32).toString('base64url');
  const keyPrefix = `${prefix}${lookup}`;
  const raw = `${keyPrefix}${secret}`;
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
