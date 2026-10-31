import { describe, it, expect } from 'vitest';
import { RULE_CATALOG } from './rules';

describe('RULE_CATALOG', () => {
  it('has unique codes', () => {
    const codes = RULE_CATALOG.map((r) => r.code);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('includes auto_block with threshold', () => {
    const ab = RULE_CATALOG.find((r) => r.code === 'auto_block');
    expect(ab).toBeTruthy();
    expect(ab!.defaultConfig.threshold).toBeGreaterThanOrEqual(50);
    expect(ab!.limits.threshold).toBeDefined();
  });

  it('every config key has limits', () => {
    for (const rule of RULE_CATALOG) {
      for (const key of Object.keys(rule.defaultConfig)) {
        expect(rule.limits[key]).toBeDefined();
      }
    }
  });
});

describe("phase2 rules", () => {
  it("includes velocity rules", () => {
    const codes = RULE_CATALOG.map((r) => r.code);
    expect(codes).toContain("brute_force");
    expect(codes).toContain("credential_stuffing");
  });
});
