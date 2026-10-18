import 'reflect-metadata';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { BadRequestException } from '@nestjs/common';
import { assertStrongPassword, blocklistFileProblems, checkPassword, fold, resetPasswordBlocklistCache } from '../src/auth/password-policy';
import { COMMON_PASSWORDS } from '../src/auth/common-passwords';
import { validateConfig } from '../src/config/validate-config';

const ok = (pw: string, ctx: any = {}) => expect(checkPassword(pw, ctx)).toEqual({ ok: true, problems: [] });
const bad = (pw: string, ctx: any = {}) => { const r = checkPassword(pw, ctx); expect(r.ok).toBe(false); return r.problems.join(' | '); };

describe('password policy', () => {
  afterEach(() => { delete process.env.PASSWORD_BLOCKLIST_FILE; resetPasswordBlocklistCache(); });

  describe('accepts', () => {
    it.each([
      'Violet-Harbor-Lantern-84', 'correct horse battery staple', 'my dog Biscuit hates thunder storms', 'tr0ub4dor&3-and-more-words',
      'Kx9#vLq2$mWz8!pR', 'purple elephants dance quietly', 'The 7 owls crossed Marina Bridge at noon',
    ])('%s', (pw) => ok(pw));
  });

  describe('length, in plain words', () => {
    it('says how short it is', () => { expect(bad('Short-1!')).toContain('at least 12 characters long (this one has 8)'); });
    it('refuses empty and missing', () => { expect(bad('')).toContain('at least 12'); expect(checkPassword(undefined as any).ok).toBe(false); });
    it('refuses over 128', () => { expect(bad('Ab1-'.repeat(40))).toContain('at most 128'); });
    it('accepts exactly 12 and 128 (when otherwise fine)', () => { ok('Xq7-Lm2-Vb9z'); const long = Array.from({ length: 128 }, (_, i) => String.fromCharCode(65 + ((i * 7 + i * i * 3) % 26)) + (i % 5 === 0 ? String(i % 10) : '')).join('').slice(0, 128);
      expect(long).toHaveLength(128); ok(long); });
    it('does not pile other complaints on a password that is already too short', () => { expect(checkPassword('password').problems).toHaveLength(1); });
  });

  describe('common passwords', () => {
    it.each([
      'password1234', 'Password123456', 'P@ssw0rd!!!!!', 'qwertyuiop12', 'iloveyou12345', 'letmein123456', 'Welcome123456!', 'administrator1',
      'Qwerty123456!', 'football123456', 'sunshine1234567', '1qaz2wsx3edc4rfv', 'Nigeria2024!!!!',
    ])('refuses %s', (pw) => { expect(bad(pw)).toMatch(/common password/); });
    it('refuses look-alike substitutions of a common word', () => { expect(bad('P4$$w0rd-----')).toMatch(/common/); });
    it('does not refuse a long passphrase that merely contains a common word', () => { ok('my freedom is worth a lot of money to me'); ok('football on sunday with grandmother'); });
    it('refuses a common password typed twice', () => { expect(bad('trustno1trustno1')).toMatch(/repeats/); });
    it('folds look-alikes and punctuation', () => { expect(fold('P@ssw0rd')).toBe(fold('password')); expect(fold('Pass-Word')).toBe('password'); });
    it('has a bounded built-in list (not a breach database)', () => { expect(COMMON_PASSWORDS.length).toBeGreaterThan(300); expect(COMMON_PASSWORDS.length).toBeLessThan(5000); });
    it('explains what to do instead', () => { expect(bad('password1234')).toContain('unrelated words'); });
  });

  describe('patterns', () => {
    it.each(['aaaaaaaaaaaa', 'abababababab', '123123123123', 'zzzzzzzzzzzy', 'xyxyxyxyxyxy', 'violetvioletviolet'])('refuses repetition: %s', (pw) => { expect(bad(pw)).toMatch(/repeats/); });
    it.each(['abcdefghijkl', 'cdefghijklmn', 'zyxwvutsrqpo', '987654321098'])('refuses a run in order: %s', (pw) => { expect(bad(pw)).toMatch(/in order|keyboard/); });
    it.each(['asdfghjklzxc', 'zxcvbnmasdfg', 'mnbvcxzlkjhg'])('refuses a keyboard walk: %s', (pw) => { expect(bad(pw)).toMatch(/keyboard|common/); });
    it('refuses only numbers', () => { expect(bad('482910573816')).toContain('only numbers'); });
    it('allows a few ordered characters inside a good password', () => { ok('abc-Violet-Harbor-Lantern-123'); });
  });

  describe('your own details', () => {
    const ctx = { email: 'amaka.okafor@example.com', name: 'Amaka Okafor' };
    it('refuses the email name part', () => { expect(bad('amaka.okafor-Violet-9', ctx)).toContain('email address or your name'); });
    it('refuses the first or last name, whatever the capitals or look-alikes', () => { expect(bad('My-OKAFOR-Violet-Harbor', ctx)).toMatch(/your name/); expect(bad('Am4ka-and-the-violet-harbor', ctx)).toMatch(/your name/); });
    it('refuses the whole email address', () => { expect(bad('amaka.okafor@example.com', ctx)).toMatch(/your name/); });
    it('ignores very short parts, so they cannot block everyone', () => { ok('Violet-Harbor-Lantern-84', { email: 'al@example.com', name: 'Al Li' }); });
    it('works with no details given', () => { ok('Violet-Harbor-Lantern-84', {}); ok('Violet-Harbor-Lantern-84', { email: null, name: null }); });
  });

  it('reports every problem at once, so they can be fixed together', () => {
    const r = checkPassword('amakaamakaamaka', { email: 'amaka@example.com', name: 'Amaka' });
    expect(r.problems.length).toBeGreaterThanOrEqual(2);
  });

  describe('assertStrongPassword', () => {
    it('throws 400 with the problems as a list and a code', () => {
      try { assertStrongPassword('password1234'); throw new Error('should throw'); } catch (e: any) {
        expect(e).toBeInstanceOf(BadRequestException);
        expect(e.getResponse()).toMatchObject({ code: 'weak_password', message: expect.arrayContaining([expect.stringContaining('common password')]) });
      }
    });
    it('does nothing for a good password', () => { expect(() => assertStrongPassword('Violet-Harbor-Lantern-84')).not.toThrow(); });
    it('never puts the password in the error', () => {
      try { assertStrongPassword('Zq9-secret-xx'); } catch (e: any) { expect(JSON.stringify(e.getResponse())).not.toContain('Zq9-secret-xx'); }
    });
  });

  describe('extending the list (PASSWORD_BLOCKLIST_FILE)', () => {
    const file = () => { const f = join(mkdtempSync(join(tmpdir(), 'pl-')), 'block.txt'); return f; };
    it('blocks the entries in the file, with comments and blank lines ignored', () => {
      const f = file(); writeFileSync(f, '# our company words\n\nbluebirdhq\r\n  Orchid-Lagos-Office  \n');
      process.env.PASSWORD_BLOCKLIST_FILE = f;
      expect(bad('BluebirdHQ-2026-x')).toMatch(/common/);
      expect(bad('orchid lagos office')).toMatch(/common/);
      ok('Violet-Harbor-Lantern-84');
    });
    it('picks up a changed file without a restart', () => {
      const f = file(); writeFileSync(f, 'firstword\n'); process.env.PASSWORD_BLOCKLIST_FILE = f;
      ok('Marigold-River-Stone-55');
      const later = new Date(Date.now() + 5000);
      writeFileSync(f, 'marigoldriverstone\n'); require('fs').utimesSync(f, later, later);
      expect(bad('Marigold-River-Stone-55')).toMatch(/common/);
    });
    it('startup refuses a missing file and accepts none or a good one', () => {
      expect(blocklistFileProblems({} as any)).toEqual([]);
      expect(blocklistFileProblems({ PASSWORD_BLOCKLIST_FILE: '/no/such/file.txt' } as any)[0]).toContain('does not exist');
      const f = file(); writeFileSync(f, 'x\n');
      expect(blocklistFileProblems({ PASSWORD_BLOCKLIST_FILE: f } as any)).toEqual([]);
      const base: any = { NODE_ENV: 'development', JWT_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), API_KEY_HASH_PEPPER: 'c'.repeat(20), DATABASE_URL: 'mysql://u:p@h/d', PASSWORD_BLOCKLIST_FILE: '/no/such/file.txt' };
      expect(validateConfig(base).errors.join(' ')).toContain('PASSWORD_BLOCKLIST_FILE');
    });
  });
});
