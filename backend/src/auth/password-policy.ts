import { BadRequestException } from '@nestjs/common';
import { existsSync, readFileSync, statSync } from 'fs';
import { COMMON_PASSWORDS } from './common-passwords';

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

/** Folds look-alike characters together and drops everything but letters and digits, so "P@ssw0rd!" is "password". */
export function fold(s: string): string {
  return String(s).toLowerCase()
    .replace(/[0]/g, 'o').replace(/[1!|]/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/@/g, 'a').replace(/\$/g, 's')
    .replace(/[^a-z0-9]/g, '');
}

const BUILT_IN = new Set(COMMON_PASSWORDS.map(fold).filter((e) => e.length > 0));
const ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];
const WALKS = [...ROWS, ...ROWS.map((r) => [...r].reverse().join(''))];

let extra: { path: string; mtime: number; entries: Set<string> } | null = null;
/** Extra entries from PASSWORD_BLOCKLIST_FILE (one per line, # comments allowed). Re-read only when the file changes. */
function extraEntries(): Set<string> {
  const path = process.env.PASSWORD_BLOCKLIST_FILE;
  if (!path) return new Set();
  const m = statSync(path).mtimeMs;
  if (extra && extra.path === path && extra.mtime === m) return extra.entries;
  const text = readFileSync(path, 'utf8');
  const entries = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const f = fold(t);
    if (f) entries.add(f);
    if (entries.size >= 2_000_000) break;
  }
  extra = { path, mtime: m, entries };
  return entries;
}
/** For tests. */
export function resetPasswordBlocklistCache() { extra = null; }

/** Problems with the blocklist file setting, for startup validation. Empty when fine or unset. */
export function blocklistFileProblems(env: NodeJS.ProcessEnv = process.env): string[] {
  const p = env.PASSWORD_BLOCKLIST_FILE;
  if (!p) return [];
  if (!existsSync(p)) return [`PASSWORD_BLOCKLIST_FILE points to ${p}, which does not exist.`];
  try { if (statSync(p).size > 50 * 1024 * 1024) return [`PASSWORD_BLOCKLIST_FILE ${p} is larger than 50 MB.`]; } catch { return [`PASSWORD_BLOCKLIST_FILE ${p} cannot be read.`]; }
  return [];
}

function isCommon(folded: string, trimmedLetters: string): boolean {
  const extras = extraEntries();
  const has = (s: string) => s.length > 0 && (BUILT_IN.has(s) || extras.has(s));
  if (has(folded) || has(trimmedLetters)) return true;
  // Built from a common password with only a few characters added, such as "qwerty123456".
  for (const set of [BUILT_IN, extras]) {
    for (const entry of set) {
      if (entry.length >= 6 && folded.length - entry.length <= 6 && folded.length >= entry.length && folded.includes(entry)) return true;
    }
  }
  return false;
}

function isRepetitive(pw: string): boolean {
  const lower = pw.toLowerCase();
  const counts = new Map<string, number>();
  for (const c of lower) counts.set(c, (counts.get(c) ?? 0) + 1);
  if (Math.max(...counts.values()) / lower.length >= 0.75) return true;           // aaaaaaaaaaaab
  return /^(.+?)\1+$/.test(lower);                                                  // abababababab, 123123123123, trustno1trustno1
}

function isSequence(pw: string): boolean {
  const lower = pw.toLowerCase();
  let best = 1; let run = 1; let dir = 0;
  for (let i = 1; i < lower.length; i++) {
    const d = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    if ((d === 1 || d === -1) && (dir === 0 || d === dir)) { run++; dir = d; } else { run = (d === 1 || d === -1) ? 2 : 1; dir = (d === 1 || d === -1) ? d : 0; }
    best = Math.max(best, run);
  }
  return best / lower.length >= 0.7 && best >= 8;                                  // 123456789012, abcdefghijkl
}

function usesKeyboardWalk(pw: string): boolean {
  const lower = pw.toLowerCase();
  for (let i = 0; i + 8 <= lower.length; i++) {
    const w = lower.slice(i, i + 8);
    if (WALKS.some((row) => row.includes(w))) return true;
  }
  return false;
}

export interface PasswordContext { email?: string | null; name?: string | null }
export interface PasswordCheck { ok: boolean; problems: string[] }

/**
 * Checks a new password. Every refusal is a plain sentence a person can act on. All the problems found
 * are returned (not only the first), so someone can fix them in one go. Never logs or stores the password.
 */
export function checkPassword(password: string, ctx: PasswordContext = {}): PasswordCheck {
  const problems: string[] = [];
  const pw = String(password ?? '');
  if (pw.length < MIN_PASSWORD_LENGTH) problems.push(`The password must be at least ${MIN_PASSWORD_LENGTH} characters long (this one has ${pw.length}).`);
  if (pw.length > MAX_PASSWORD_LENGTH) problems.push(`The password must be at most ${MAX_PASSWORD_LENGTH} characters long.`);
  if (pw.length >= MIN_PASSWORD_LENGTH && pw.length <= MAX_PASSWORD_LENGTH) {
    if (/^\d+$/.test(pw)) problems.push('The password cannot be only numbers.');
    const folded = fold(pw);
    const trimmed = fold(pw.replace(/[^A-Za-z]+$/, ''));
    if (isCommon(folded, trimmed)) problems.push('This is a very common password, or a common password with a few characters added. Choose something only you would think of, such as three or four unrelated words.');
    if (isRepetitive(pw)) problems.push('The password repeats the same characters or the same short pattern. Mix it up.');
    else if (isSequence(pw) || usesKeyboardWalk(pw)) problems.push('The password is a run of letters or numbers in order, or a pattern from the keyboard. Those are guessed first.');
    const local = fold(String(ctx.email ?? '').split('@')[0] ?? '');
    const nameParts = String(ctx.name ?? '').split(/[\s.,_-]+/).map(fold).filter((p) => p.length >= 3);
    if ((local.length >= 3 && folded.includes(local)) || nameParts.some((p) => folded.includes(p))) {
      problems.push('The password contains your email address or your name. Choose one that does not.');
    }
  }
  return { ok: problems.length === 0, problems };
}

/** Throws 400 with every problem as a plain sentence (message is a list, like validation errors) and code weak_password. */
export function assertStrongPassword(password: string, ctx: PasswordContext = {}): void {
  const r = checkPassword(password, ctx);
  if (!r.ok) throw new BadRequestException({ message: r.problems, code: 'weak_password' });
}
