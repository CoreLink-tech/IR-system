import { createHash, randomBytes, timingSafeEqual } from 'crypto';

export function generateApiKey(prefix = 'IRS_'): { raw: string; prefix: string; hash: string } {
  // The lookup prefix MUST be the leading part of the raw key, because
  // verifyApiKey() derives it by slicing the presented key.
  const lookup = randomBytes(8).toString('hex'); // 16 chars
  const secret = randomBytes(32).toString('base64url');
  const keyPrefix = `${prefix}${lookup}`;
  const raw = `${keyPrefix}${secret}`;
  const hash = hashApiKey(raw);
  return { raw, prefix: keyPrefix, hash };
}

/** Hash with the current pepper (and optionally a specific pepper for migration checks). */
export function hashApiKey(raw: string, pepper?: string): string {
  const p = pepper !== undefined ? pepper : (process.env.API_KEY_HASH_PEPPER || '');
  return createHash('sha256').update(raw + p).digest('hex');
}

/**
 * Verify a presented key against a stored hash.
 * Tries the current pepper first, then the previous pepper (if set).
 * Returns which pepper matched so the caller can rehash to the current one.
 */
export function verifyApiKeyHash(raw: string, storedHash: string): { ok: boolean; usedPrevious: boolean } {
  const current = process.env.API_KEY_HASH_PEPPER || '';
  if (safeEqual(hashApiKey(raw, current), storedHash)) {
    return { ok: true, usedPrevious: false };
  }
  const previous = (process.env.API_KEY_HASH_PEPPER_PREVIOUS || '').trim();
  if (previous && safeEqual(hashApiKey(raw, previous), storedHash)) {
    return { ok: true, usedPrevious: true };
  }
  return { ok: false, usedPrevious: false };
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
