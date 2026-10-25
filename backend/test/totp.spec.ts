import { randomBytes } from 'crypto';
import { base32Decode, base32Encode, hotp, newTotpSecret, otpauthUri, timeStep, totp, verifyTotp } from '../src/auth/totp';
import {
  decryptSecret, encryptSecret, hashRecoveryCode, hashRecoveryCodeAll, keyProblems, loadKeyRing, looksLikeRecoveryCode,
  newRecoveryCode, normalizeRecoveryCode, parseKey, reencrypt, usesCurrentKey,
} from '../src/auth/two-factor.crypto';

describe('base32 (RFC 4648 test vectors)', () => {
  it.each([['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']])('%j', (plain, enc) => {
    expect(base32Encode(Buffer.from(plain))).toBe(enc);
    expect(base32Decode(enc).toString()).toBe(plain);
  });
  it('decodes lower case, spaces, dashes and padding the way people type or paste them', () => { expect(base32Decode('mzxw 6ytb-oi======').toString()).toBe('foobar'); });
  it('refuses characters that are not base32', () => { expect(() => base32Decode('MZXW1')).toThrow(); });
  it('round trips random data', () => { for (let i = 0; i < 50; i++) { const b = randomBytes(1 + (i % 33)); expect(base32Decode(base32Encode(b)).equals(b)).toBe(true); } });
});

describe('HOTP / TOTP against the published test vectors', () => {
  // RFC 4226 appendix D
  const hotpSecret = Buffer.from('12345678901234567890');
  it.each(['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'])('HOTP counter %#', (expected) => {
    const i = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'].indexOf(expected);
    expect(hotp(hotpSecret, i)).toBe(expected);
  });
  // RFC 6238 appendix B (SHA-1), 8 digits; the last 6 are our 6-digit code
  const secret = base32Encode(hotpSecret);
  it.each([[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']])('TOTP at %i', (t, eight) => {
    expect(totp(secret, new Date(t * 1000), 8)).toBe(eight);
    expect(totp(secret, new Date(t * 1000))).toBe(eight.slice(-6));
  });
});

describe('verifying a code', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  const T = new Date(1111111111 * 1000);               // code 050471
  it('accepts the current code and returns its step', () => { expect(verifyTotp(secret, '050471', T)).toEqual({ ok: true, step: timeStep(T) }); });
  it('accepts a code with spaces, as authenticator apps show it', () => { expect(verifyTotp(secret, '050 471', T).ok).toBe(true); });
  it('accepts the step before and after (a clock that is up to 30 seconds off) and no further', () => {
    const prev = totp(secret, new Date(T.getTime() - 30_000)); const next = totp(secret, new Date(T.getTime() + 30_000));
    const far = totp(secret, new Date(T.getTime() + 60_000));
    expect(verifyTotp(secret, prev, T).ok).toBe(true); expect(verifyTotp(secret, next, T).ok).toBe(true);
    expect(verifyTotp(secret, far, T)).toMatchObject({ ok: false, reason: 'wrong' });
  });
  it('the window is adjustable', () => {
    const far = totp(secret, new Date(T.getTime() + 60_000));
    expect(verifyTotp(secret, far, T, { window: 2 }).ok).toBe(true);
    expect(verifyTotp(secret, totp(secret, new Date(T.getTime() + 30_000)), T, { window: 0 }).ok).toBe(false);
  });
  it('refuses a wrong code', () => { expect(verifyTotp(secret, '000000', T)).toMatchObject({ ok: false, reason: 'wrong' }); });
  it.each(['', '12345', '1234567', 'abcdef', '05047l', null, undefined])('refuses a code that is not six digits: %j', (c) => { expect(verifyTotp(secret, c as any, T)).toMatchObject({ ok: false, reason: 'format' }); });
  it('refuses a code that was already used, even inside its window (replay)', () => {
    const first = verifyTotp(secret, '050471', T);
    expect(verifyTotp(secret, '050471', T, { lastStep: first.step })).toMatchObject({ ok: false, reason: 'replay' });
    const earlier = totp(secret, new Date(T.getTime() - 30_000));                  // an older code than the last used is a replay too
    expect(verifyTotp(secret, earlier, T, { lastStep: first.step })).toMatchObject({ ok: false, reason: 'replay' });
    const later = totp(secret, new Date(T.getTime() + 30_000));                    // a newer one is fine
    expect(verifyTotp(secret, later, T, { lastStep: first.step }).ok).toBe(true);
  });
  it('a code for a different secret does not verify', () => { expect(verifyTotp(newTotpSecret(), '050471', T).ok).toBe(false); });
  it('new secrets are 160 bits in base32 and differ each time', () => { const a = newTotpSecret(); expect(a).toMatch(/^[A-Z2-7]{32}$/); expect(newTotpSecret()).not.toBe(a); });
});

describe('the address an authenticator app reads', () => {
  it('contains the secret, issuer and account, safely encoded', () => {
    const u = otpauthUri('JBSWY3DPEHPK3PXP', 'amaka@example.com', 'Security Dashboard');
    expect(u).toBe('otpauth://totp/Security%20Dashboard:amaka%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Security%20Dashboard&algorithm=SHA1&digits=6&period=30');
    expect(otpauthUri('A', 'a b&c@d', 'X&Y')).not.toMatch(/[ &]c/);
  });
});

describe('secrets at rest', () => {
  const keyA = randomBytes(32).toString('hex'); const keyB = randomBytes(32).toString('hex');
  const ringA = loadKeyRing({ TOTP_ENCRYPTION_KEY: keyA } as any)!;
  it('round trips and never contains the secret', () => {
    const s = newTotpSecret(); const enc = encryptSecret(s, ringA);
    expect(decryptSecret(enc, ringA)).toBe(s); expect(enc).not.toContain(s); expect(enc.startsWith('v1.')).toBe(true);
  });
  it('is different every time (random IV)', () => { expect(encryptSecret('X', ringA)).not.toBe(encryptSecret('X', ringA)); });
  it('detects tampering', () => {
    const enc = encryptSecret(newTotpSecret(), ringA).split('.');
    enc[4] = (enc[4][0] === 'A' ? 'B' : 'A') + enc[4].slice(1);
    expect(() => decryptSecret(enc.join('.'), ringA)).toThrow();
  });
  it('is unreadable with another key, and says why', () => {
    const ringB = loadKeyRing({ TOTP_ENCRYPTION_KEY: keyB } as any)!;
    expect(() => decryptSecret(encryptSecret('X', ringA), ringB)).toThrow(/no longer configured/);
  });
  it('a key can be replaced: old values are read with the previous key, new ones use the current', () => {
    const old = encryptSecret('SECRET1', ringA);
    const ringNew = loadKeyRing({ TOTP_ENCRYPTION_KEY: keyB, TOTP_ENCRYPTION_KEY_PREVIOUS: keyA } as any)!;
    expect(decryptSecret(old, ringNew)).toBe('SECRET1');
    expect(usesCurrentKey(old, ringNew)).toBe(false);
    const moved = reencrypt(old, ringNew);
    expect(usesCurrentKey(moved, ringNew)).toBe(true);
    expect(decryptSecret(moved, loadKeyRing({ TOTP_ENCRYPTION_KEY: keyB } as any)!)).toBe('SECRET1');
  });
  it('refuses garbage', () => { for (const g of ['', 'x', 'v2.a.b.c.d', 'v1.a.b.c']) expect(() => decryptSecret(g, ringA)).toThrow(); });
  it('accepts a key as 64 hex characters or as base64, and nothing else', () => {
    const raw = randomBytes(32);
    expect(parseKey(raw.toString('hex'))!.equals(raw)).toBe(true);
    expect(parseKey(raw.toString('base64'))!.equals(raw)).toBe(true);
    for (const bad of ['', 'short', 'z'.repeat(64), randomBytes(16).toString('hex'), randomBytes(31).toString('base64')]) expect(parseKey(bad)).toBeNull();
  });
  it('explains key problems in plain sentences', () => {
    expect(keyProblems({} as any)).toEqual([]);
    expect(keyProblems({ TOTP_ENCRYPTION_KEY: 'short' } as any)[0]).toContain('openssl rand -hex 32');
    expect(keyProblems({ TOTP_ENCRYPTION_KEY_PREVIOUS: keyA } as any).join()).toContain('is not');
    expect(loadKeyRing({} as any)).toBeNull();
  });
});

describe('recovery codes', () => {
  const ring = loadKeyRing({ TOTP_ENCRYPTION_KEY: randomBytes(32).toString('hex') } as any)!;
  it('are 80 bits, easy to read from paper, and different each time', () => {
    const c = newRecoveryCode(); expect(c).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
    expect(new Set(Array.from({ length: 200 }, newRecoveryCode)).size).toBe(200);
  });
  it('are recognised however they are typed', () => {
    const c = newRecoveryCode();
    expect(looksLikeRecoveryCode(c)).toBe(true); expect(looksLikeRecoveryCode(c.toLowerCase().replace(/-/g, ' '))).toBe(true);
    expect(normalizeRecoveryCode(c.toLowerCase())).toBe(c.replace(/-/g, ''));
    for (const no of ['123456', 'ABCD-EFGH', '', 'OOOO-1111-IIII-0000']) expect(looksLikeRecoveryCode(no)).toBe(false);
  });
  it('are stored as a keyed hash that does not reveal them, and the same code always hashes the same', () => {
    const c = newRecoveryCode(); const h = hashRecoveryCode(c, ring);
    expect(h).toMatch(/^[0-9a-f]{64}$/); expect(h).not.toContain(c.replace(/-/g, ''));
    expect(hashRecoveryCode(c.toLowerCase(), ring)).toBe(h);
    expect(hashRecoveryCode(newRecoveryCode(), ring)).not.toBe(h);
    const other = loadKeyRing({ TOTP_ENCRYPTION_KEY: randomBytes(32).toString('hex') } as any)!;
    expect(hashRecoveryCode(c, other)).not.toBe(h);
  });
  it('keep working across a key change (the hash under the previous key is also checked)', () => {
    const c = newRecoveryCode(); const oldHash = hashRecoveryCode(c, ring);
    const next = loadKeyRing({ TOTP_ENCRYPTION_KEY: randomBytes(32).toString('hex'), TOTP_ENCRYPTION_KEY_PREVIOUS: ring.current.toString('hex') } as any)!;
    expect(hashRecoveryCodeAll(c, next)).toContain(oldHash);
    expect(hashRecoveryCodeAll(c, ring)).toEqual([oldHash]);
  });
});
