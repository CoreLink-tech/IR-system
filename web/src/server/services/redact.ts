/** Shared redaction for log ingest and metadata scrubbing. */

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-+=/]+/gi;
const AUTH_HEADER_RE = /Authorization\s*[:=]\s*["']?[^"'\s,;]+/gi;
const COOKIE_RE = /(?:Set-)?Cookie\s*[:=]\s*[^;\n]+/gi;
const SENSITIVE_KV_RE =
  /(["']?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|cvv|cvc|card(?:_number)?|authorization)["']?\s*[:=]\s*)(["']?)[^"'\s&,;]+(["']?)/gi;

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

/** Replace Luhn-valid 13–19 digit sequences (spaces/dashes allowed). */
export function redactPan(text: string): string {
  return text.replace(/(?:\d[ \-]*){13,19}/g, (match) => {
    const digits = match.replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnOk(digits)) {
      return '[REDACTED_PAN]';
    }
    return match;
  });
}

export type RedactOptions = {
  /** When true (default), replace emails. */
  redactEmails?: boolean;
};

export function redactText(input: string, opts: RedactOptions = {}): string {
  let s = input;
  s = redactPan(s);
  s = s.replace(BEARER_RE, 'Bearer [REDACTED]');
  s = s.replace(AUTH_HEADER_RE, 'Authorization: [REDACTED]');
  s = s.replace(COOKIE_RE, (m) => (m.toLowerCase().startsWith('set-') ? 'Set-Cookie: [REDACTED]' : 'Cookie: [REDACTED]'));
  s = s.replace(SENSITIVE_KV_RE, '$1$2[REDACTED]$3');
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
