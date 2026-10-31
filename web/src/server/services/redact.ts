/** Shared redaction for log ingest and metadata scrubbing. */

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-+=/]+/gi;
const AUTH_HEADER_RE = /Authorization\s*[:=]\s*["']?[^"'\s,;]+/gi;
const COOKIE_RE = /(?:Set-)?Cookie\s*[:=]\s*[^;\n]+/gi;

function luhnOk(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function looksLikeCardPrefix(digits: string): boolean {
  if (digits.startsWith('4') && digits.length >= 13) return true; // Visa
  if (/^5[1-5]/.test(digits)) return true; // Mastercard
  if (/^2(2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)/.test(digits)) return true; // Mastercard 2221–2720
  if (/^3[47]/.test(digits)) return true; // Amex
  if (/^6011/.test(digits) || /^65/.test(digits)) return true; // Discover
  if (/^506(0[9][9]|1[0-9][0-8])/.test(digits) || /^6500(0[2-9]|1\d|2[0-7])/.test(digits)) return true; // Verve-ish
  return false;
}

function isEpochMs(digits: string): boolean {
  if (digits.length !== 13) return false;
  const n = Number(digits);
  return n >= 1_000_000_000_000 && n <= 2_999_999_999_999;
}

/** Replace Luhn-valid card-like digit runs (known prefixes only; skip epoch-ms). */
export function redactPan(text: string): string {
  return text.replace(/(?:\d[ \-]*){13,19}/g, (match) => {
    const digits = match.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return match;
    if (isEpochMs(digits)) return match;
    if (!looksLikeCardPrefix(digits)) return match;
    if (!luhnOk(digits)) return match;
    return '[REDACTED_PAN]';
  });
}

export type RedactOptions = {
  redactEmails?: boolean;
};

export function redactText(input: string, opts: RedactOptions = {}): string {
  let s = input;
  s = redactPan(s);
  s = s.replace(BEARER_RE, 'Bearer [REDACTED]');
  s = s.replace(AUTH_HEADER_RE, 'Authorization: [REDACTED]');
  s = s.replace(COOKIE_RE, (m) =>
    m.toLowerCase().startsWith('set-') ? 'Set-Cookie: [REDACTED]' : 'Cookie: [REDACTED]',
  );
  if (opts.redactEmails !== false) {
    s = s.replace(EMAIL_RE, '[REDACTED_EMAIL]');
  }
  return s;
}

export function redactJsonValue(value: unknown, opts: RedactOptions = {}): unknown {
  if (typeof value === 'string') return redactText(value, opts);
  if (Array.isArray(value)) return value.map((v) => redactJsonValue(v, opts));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (/password|passwd|pwd|secret|token|api[_-]?key|apikey|cvv|cvc|card/i.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactJsonValue(v, opts);
      }
    }
    return out;
  }
  return value;
}
