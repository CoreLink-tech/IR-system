import { describe, it, expect } from 'vitest';
import { RULE_CATALOG } from './rules';

describe('Phase 0 scoring defaults', () => {
  it('login_failed base + MEDIUM reaches incident threshold (≥35)', () => {
    const login = RULE_CATALOG.find((r) => r.code === 'login_failed')!;
    const score = (login.defaultConfig.baseScore ?? 0) + 10; // MEDIUM
    expect(score).toBeGreaterThanOrEqual(35);
  });

  it('auto_block default threshold is reachable by payment+CRITICAL', () => {
    const payment = RULE_CATALOG.find((r) => r.code === 'payment')!;
    const ab = RULE_CATALOG.find((r) => r.code === 'auto_block')!;
    const score = (payment.defaultConfig.baseScore ?? 0) + 30; // CRITICAL
    expect(score).toBeGreaterThanOrEqual(ab.defaultConfig.threshold ?? 999);
  });

  it('auto_block default is 70 not 85', () => {
    const ab = RULE_CATALOG.find((r) => r.code === 'auto_block')!;
    expect(ab.defaultConfig.threshold).toBe(70);
  });
});
