import { describe, it, expect } from 'vitest';
import { redactText, redactPan } from './redact';

describe('redact', () => {
  it('redacts Luhn-valid PAN', () => {
    // Visa test number
    expect(redactPan('card 4111 1111 1111 1111 end')).toContain('[REDACTED_PAN]');
  });

  it('keeps non-Luhn digit runs', () => {
    const s = redactPan('order 1234567890123');
    expect(s).not.toContain('[REDACTED_PAN]');
  });

  it('redacts bearer and cookies', () => {
    const s = redactText('Authorization: Bearer abc.def.ghi Cookie: session=xyz');
    expect(s).toMatch(/REDACTED/);
    expect(s).not.toContain('abc.def');
  });

  it('redacts password fields', () => {
    const s = redactText('password=secret123&user=a');
    expect(s).toContain('[REDACTED]');
    expect(s).not.toContain('secret123');
  });

  it('redacts emails by default', () => {
    expect(redactText('mail me@example.com')).toContain('[REDACTED_EMAIL]');
  });

  it('can skip email redaction', () => {
    expect(redactText('mail me@example.com', { redactEmails: false })).toContain('me@example.com');
  });
});
