import { redact } from '../src/common/utils/redact';

describe('redact', () => {
  it('redacts password fields in JSON-like strings', () => {
    const out = redact({ password: 'hunter2hunter2', email: 'a@example.com' });
    expect(out).not.toMatch(/hunter2/);
    expect(out).toMatch(/\[redacted\]/);
    expect(out).toMatch(/a@example.com/);
  });

  it('redacts Bearer tokens', () => {
    const out = redact('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def');
    expect(out).toMatch(/Bearer \[redacted\]/);
    expect(out).not.toMatch(/eyJ/);
  });

  it('redacts IRS_ API keys', () => {
    const out = redact('key=IRS_abcd1234efgh5678secretpart');
    expect(out).toMatch(/IRS_\[redacted\]/);
  });

  it('redacts refresh cookie values', () => {
    const out = redact('Cookie: ir_rt=supersecrettokenvalue; Path=/');
    expect(out).toMatch(/ir_rt=\[redacted\]/);
    expect(out).not.toMatch(/supersecret/);
  });
});
