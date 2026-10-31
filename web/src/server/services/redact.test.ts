import { describe, it, expect } from 'vitest';
import { redactText, redactPan, redactJsonValue } from './redact';

describe('redact', () => {
  it('redacts Visa test PAN', () => {
    expect(redactPan('card 4111 1111 1111 1111 end')).toContain('[REDACTED_PAN]');
  });

  it('does not redact 1000 epoch-ms timestamps', () => {
    for (let i = 0; i < 1000; i++) {
      const ts = String(1_700_000_000_000 + i);
      expect(redactPan(ts)).toBe(ts);
    }
  });

  it('redacts card in path-like string', () => {
    expect(redactText('/pay?card=4111111111111111')).toContain('[REDACTED_PAN]');
  });

  it('redacts password object fully', () => {
    const o = redactJsonValue({ password: 'my secret pass', path: '/ok' }) as Record<string, unknown>;
    expect(o.password).toBe('[REDACTED]');
    expect(JSON.stringify(o)).not.toContain('secret');
  });

  it('redacts bearer tokens', () => {
    expect(redactText('Bearer abc.def.ghi')).not.toContain('abc.def');
  });
});
