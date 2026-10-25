/**
 * Unit tests for JWT key rotation helpers and API-key pepper dual verification.
 * Pure functions only — no database, no Nest context.
 */
import {
  loadAccessKeyRing,
  loadRefreshKeyRing,
  secretForKid,
  jwtKeyProblems,
} from '../src/auth/jwt-keys';
import {
  hashApiKey,
  verifyApiKeyHash,
  generateApiKey,
  safeEqual,
} from '../src/common/utils/crypto.util';
import { csrfTokenFor, checkCookieRequest } from '../src/auth/session-cookie';

describe('JWT key ring', () => {
  const env = {
    JWT_SECRET: 'a'.repeat(48),
    JWT_SECRET_PREVIOUS: 'b'.repeat(48),
    JWT_KEY_ID: 'v2',
    JWT_KEY_ID_PREVIOUS: 'v1',
    JWT_REFRESH_SECRET: 'c'.repeat(48),
    JWT_REFRESH_SECRET_PREVIOUS: 'd'.repeat(48),
  };

  it('resolves current and previous kids', () => {
    const ring = loadAccessKeyRing(env as any);
    expect(secretForKid(ring, 'v2')).toBe(env.JWT_SECRET);
    expect(secretForKid(ring, 'v1')).toBe(env.JWT_SECRET_PREVIOUS);
    expect(secretForKid(ring, 'unknown')).toBeNull();
  });

  it('legacy tokens with no kid try current then previous', () => {
    const ring = loadAccessKeyRing(env as any);
    expect(secretForKid(ring, undefined)).toBe(env.JWT_SECRET);
    expect(secretForKid(ring, null)).toBe(env.JWT_SECRET);
  });

  it('rejects identical current and previous secrets', () => {
    const problems = jwtKeyProblems({
      JWT_SECRET: 'same',
      JWT_SECRET_PREVIOUS: 'same',
      JWT_REFRESH_SECRET: 'x'.repeat(32),
    } as any);
    expect(problems.some((p) => p.includes('JWT_SECRET and JWT_SECRET_PREVIOUS'))).toBe(true);
  });

  it('refresh ring loads independently', () => {
    const ring = loadRefreshKeyRing(env as any);
    expect(ring.current).toBe(env.JWT_REFRESH_SECRET);
    expect(ring.previous).toBe(env.JWT_REFRESH_SECRET_PREVIOUS);
  });
});

describe('API key pepper dual verification', () => {
  const current = 'current-pepper-value-16+';
  const previous = 'previous-pepper-value-16';

  beforeEach(() => {
    process.env.API_KEY_HASH_PEPPER = current;
    process.env.API_KEY_HASH_PEPPER_PREVIOUS = previous;
  });

  afterEach(() => {
    delete process.env.API_KEY_HASH_PEPPER;
    delete process.env.API_KEY_HASH_PEPPER_PREVIOUS;
  });

  it('accepts a hash made with the current pepper', () => {
    const raw = 'IRS_abcd1234efgh5678' + 'secretpart';
    const stored = hashApiKey(raw, current);
    const r = verifyApiKeyHash(raw, stored);
    expect(r.ok).toBe(true);
    expect(r.usedPrevious).toBe(false);
  });

  it('accepts a hash made with the previous pepper and flags migration', () => {
    const raw = 'IRS_abcd1234efgh5678' + 'secretpart';
    const stored = hashApiKey(raw, previous);
    const r = verifyApiKeyHash(raw, stored);
    expect(r.ok).toBe(true);
    expect(r.usedPrevious).toBe(true);
  });

  it('rejects a wrong key', () => {
    const stored = hashApiKey('IRS_abcd1234efgh5678right', current);
    const r = verifyApiKeyHash('IRS_abcd1234efgh5678wrong', stored);
    expect(r.ok).toBe(false);
  });

  it('generateApiKey uses the current pepper', () => {
    const g = generateApiKey('IRS_');
    expect(g.raw.startsWith('IRS_')).toBe(true);
    expect(safeEqual(g.hash, hashApiKey(g.raw, current))).toBe(true);
  });
});

describe('CSRF dual-key acceptance', () => {
  const current = 'c'.repeat(48);
  const previous = 'd'.repeat(48);

  beforeEach(() => {
    process.env.JWT_REFRESH_SECRET = current;
    process.env.JWT_REFRESH_SECRET_PREVIOUS = previous;
    process.env.CORS_ORIGINS = 'https://dash.example.com';
  });

  afterEach(() => {
    delete process.env.JWT_REFRESH_SECRET;
    delete process.env.JWT_REFRESH_SECRET_PREVIOUS;
    delete process.env.CORS_ORIGINS;
  });

  it('csrfTokenFor always uses the current secret', () => {
    const token = 'refresh-token-value';
    const csrf = csrfTokenFor(token);
    // Recompute with current only
    const { createHash, createHmac } = require('crypto');
    const bound = createHash('sha256').update(token).digest('hex');
    const expected = createHmac('sha256', current).update(`csrf:${bound}`).digest('base64url');
    expect(csrf).toBe(expected);
  });

  it('accepts a CSRF token computed with the previous secret', () => {
    const token = 'refresh-token-value';
    const { createHash, createHmac } = require('crypto');
    const bound = createHash('sha256').update(token).digest('hex');
    const oldCsrf = createHmac('sha256', previous).update(`csrf:${bound}`).digest('base64url');
    const result = checkCookieRequest(
      { headers: { origin: 'https://dash.example.com', 'x-csrf-token': oldCsrf } },
      token,
    );
    expect(result).toBeNull();
  });

  it('rejects a CSRF token computed with an unknown secret', () => {
    const token = 'refresh-token-value';
    const { createHash, createHmac } = require('crypto');
    const bound = createHash('sha256').update(token).digest('hex');
    const bad = createHmac('sha256', 'wrong-secret').update(`csrf:${bound}`).digest('base64url');
    const result = checkCookieRequest(
      { headers: { origin: 'https://dash.example.com', 'x-csrf-token': bad } },
      token,
    );
    expect(result).toBe('token');
  });
});
