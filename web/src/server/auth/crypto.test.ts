import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateApiKey, hashApiKey, safeEqual, sha256 } from './crypto';

describe('crypto helpers', () => {
  const prev = process.env.API_KEY_HASH_PEPPER;

  beforeEach(() => {
    process.env.API_KEY_HASH_PEPPER = 'test-pepper-value-16';
    process.env.JWT_SECRET = 'x'.repeat(48);
    process.env.JWT_REFRESH_SECRET = 'y'.repeat(48);
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.API_KEY_HASH_PEPPER;
    else process.env.API_KEY_HASH_PEPPER = prev;
  });

  it('safeEqual is true for equal strings', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
  });

  it('safeEqual is false for different strings', () => {
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'ab')).toBe(false);
  });

  it('sha256 is stable', () => {
    expect(sha256('hello')).toBe(sha256('hello'));
    expect(sha256('hello')).not.toBe(sha256('world'));
  });

  it('generateApiKey includes prefix and matching hash', () => {
    const g = generateApiKey('IRS_');
    expect(g.raw.startsWith('IRS_')).toBe(true);
    expect(g.prefix.startsWith('IRS_')).toBe(true);
    expect(g.raw.startsWith(g.prefix)).toBe(true);
    expect(safeEqual(g.hash, hashApiKey(g.raw))).toBe(true);
  });
});
