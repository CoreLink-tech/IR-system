/**
 * Redact secrets from strings before they go to logs.
 * Covers passwords, tokens, codes, cookies, and common header values.
 */
const SECRET_KEYS = [
  'password', 'currentPassword', 'newPassword', 'passwordHash',
  'accessToken', 'refreshToken', 'challengeToken', 'csrfToken', 'token',
  'code', 'recoveryCode', 'totpSecret', 'secret',
  'apiKey', 'authorization', 'cookie', 'ir_rt',
  'JWT_SECRET', 'JWT_REFRESH_SECRET', 'API_KEY_HASH_PEPPER', 'TOTP_ENCRYPTION_KEY',
];

const KEY_RE = new RegExp(
  `("?(?:${SECRET_KEYS.join('|')})"\\s*[:=]\\s*)("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[A-Za-z0-9._\\-+/=]{8,})`,
  'gi',
);

const BEARER_RE = /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi;
const IRS_KEY_RE = /\bIRS_[A-Za-z0-9]+/g;
const COOKIE_RE = /ir_rt=[^;\s]+/gi;

export function redact(input: unknown): string {
  let s = typeof input === 'string' ? input : (() => {
    try { return JSON.stringify(input); } catch { return String(input); }
  })();
  s = s.replace(KEY_RE, '$1"[redacted]"');
  s = s.replace(BEARER_RE, 'Bearer [redacted]');
  s = s.replace(IRS_KEY_RE, 'IRS_[redacted]');
  s = s.replace(COOKIE_RE, 'ir_rt=[redacted]');
  return s;
}
