import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { getEnv } from '@/lib/env';

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function generateApiKey(prefix = 'IRS_'): { raw: string; prefix: string; hash: string } {
  const lookup = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('base64url');
  const keyPrefix = `${prefix}${lookup}`;
  const raw = `${keyPrefix}${secret}`;
  return { raw, prefix: keyPrefix, hash: hashApiKey(raw) };
}

export function hashApiKey(raw: string, pepper?: string): string {
  const p = pepper ?? getEnv().apiKeyPepper;
  return createHash('sha256').update(raw + p).digest('hex');
}

export function hashRefreshToken(token: string): string {
  return sha256(token);
}

export function newId(): string {
  return randomBytes(16).toString('hex');
}
