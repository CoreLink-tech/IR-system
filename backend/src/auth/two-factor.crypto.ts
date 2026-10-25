import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'crypto';

/**
 * Keys for protecting the two-step secrets in the database. The key comes from the environment
 * (TOTP_ENCRYPTION_KEY, 32 bytes as 64 hex characters or base64). TOTP_ENCRYPTION_KEY_PREVIOUS lets a key be
 * replaced without re-enrolling anyone: new secrets use the current key, old ones are still read with the
 * previous one. Each stored value says which key (by a short fingerprint) it was written with.
 */
export interface KeyRing { current: Buffer; previous?: Buffer }

export function parseKey(raw: string | undefined): Buffer | null {
  const v = String(raw ?? '').trim();
  if (!v) return null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, 'hex');
  try { const b = Buffer.from(v, 'base64'); if (b.length === 32 && b.toString('base64').replace(/=+$/, '') === v.replace(/=+$/, '')) return b; } catch { /* fall through */ }
  return null;
}

export function loadKeyRing(env: NodeJS.ProcessEnv = process.env): KeyRing | null {
  const current = parseKey(env.TOTP_ENCRYPTION_KEY);
  if (!current) return null;
  const previous = parseKey(env.TOTP_ENCRYPTION_KEY_PREVIOUS) ?? undefined;
  return { current, previous };
}

/** Problems with the key settings, as plain sentences. */
export function keyProblems(env: NodeJS.ProcessEnv = process.env): string[] {
  const out: string[] = [];
  if (env.TOTP_ENCRYPTION_KEY && !parseKey(env.TOTP_ENCRYPTION_KEY)) out.push('TOTP_ENCRYPTION_KEY must be 32 random bytes as 64 hex characters or base64 (generate one with: openssl rand -hex 32).');
  if (env.TOTP_ENCRYPTION_KEY_PREVIOUS && !parseKey(env.TOTP_ENCRYPTION_KEY_PREVIOUS)) out.push('TOTP_ENCRYPTION_KEY_PREVIOUS must be 32 random bytes as 64 hex characters or base64.');
  if (env.TOTP_ENCRYPTION_KEY_PREVIOUS && !env.TOTP_ENCRYPTION_KEY) out.push('TOTP_ENCRYPTION_KEY_PREVIOUS is set but TOTP_ENCRYPTION_KEY is not.');
  return out;
}

const fingerprint = (key: Buffer) => createHash('sha256').update(key).digest('hex').slice(0, 8);

/** AES-256-GCM. Stored as  v1.<key fingerprint>.<iv>.<tag>.<ciphertext>  (all base64url). */
export function encryptSecret(plain: string, ring: KeyRing): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', ring.current, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return ['v1', fingerprint(ring.current), iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}

export function decryptSecret(stored: string, ring: KeyRing): string {
  const [ver, fp, iv, tag, ct] = String(stored).split('.');
  if (ver !== 'v1' || !fp || !iv || !tag || !ct) throw new Error('unreadable two-step secret');
  const key = [ring.current, ring.previous].find((k) => k && fingerprint(k) === fp);
  if (!key) throw new Error('the key this two-step secret was written with is no longer configured');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}

/** Rewrites a stored secret with the current key (used after a key change). */
export const reencrypt = (stored: string, ring: KeyRing) => encryptSecret(decryptSecret(stored, ring), ring);
export const usesCurrentKey = (stored: string, ring: KeyRing) => String(stored).split('.')[1] === fingerprint(ring.current);

// ---- recovery codes ----------------------------------------------------------------------------

const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no 0 O 1 I, so they can be read from paper

/** 16 characters (80 bits), shown as XXXX-XXXX-XXXX-XXXX. */
export function newRecoveryCode(): string {
  const bytes = randomBytes(16);
  let s = ''; for (let i = 0; i < 16; i++) s += CODE_ALPHABET[bytes[i] % 32];
  return s.match(/.{4}/g)!.join('-');
}
export const normalizeRecoveryCode = (code: string) => String(code ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
export const looksLikeRecoveryCode = (code: string) => /^[A-HJ-NP-Z2-9]{16}$/.test(normalizeRecoveryCode(code));

/** Recovery codes are stored only as a keyed hash, so a copy of the database does not reveal them. */
export function hashRecoveryCode(code: string, ring: KeyRing): string {
  return createHmac('sha256', ring.current).update('recovery:' + normalizeRecoveryCode(code)).digest('hex');
}
/** The hash under the previous key too, so codes keep working across a key change. */
export function hashRecoveryCodeAll(code: string, ring: KeyRing): string[] {
  const out = [hashRecoveryCode(code, ring)];
  if (ring.previous) out.push(createHmac('sha256', ring.previous).update('recovery:' + normalizeRecoveryCode(code)).digest('hex'));
  return out;
}
