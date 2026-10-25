import { describe, it, expect } from 'vitest';

// Pure posture helper mirrored from reports for unit coverage without DB.
function postureFrom(counts: {
  criticalOpen: number;
  highOpen: number;
  open: number;
  blocks: number;
  highRiskEvents: number;
}): 'CALM' | 'ELEVATED' | 'HIGH' | 'CRITICAL' {
  if (counts.criticalOpen > 0) return 'CRITICAL';
  if (counts.highOpen >= 3 || counts.blocks >= 10) return 'HIGH';
  if (counts.open > 0 || counts.highRiskEvents > 20) return 'ELEVATED';
  return 'CALM';
}

describe('report posture logic', () => {
  it('is CALM when idle', () => {
    expect(postureFrom({ criticalOpen: 0, highOpen: 0, open: 0, blocks: 0, highRiskEvents: 0 })).toBe('CALM');
  });

  it('is CRITICAL when any critical open', () => {
    expect(postureFrom({ criticalOpen: 1, highOpen: 0, open: 1, blocks: 0, highRiskEvents: 0 })).toBe('CRITICAL');
  });

  it('is HIGH when many high opens or blocks', () => {
    expect(postureFrom({ criticalOpen: 0, highOpen: 3, open: 3, blocks: 0, highRiskEvents: 0 })).toBe('HIGH');
    expect(postureFrom({ criticalOpen: 0, highOpen: 0, open: 0, blocks: 10, highRiskEvents: 0 })).toBe('HIGH');
  });

  it('is ELEVATED for modest activity', () => {
    expect(postureFrom({ criticalOpen: 0, highOpen: 1, open: 1, blocks: 0, highRiskEvents: 0 })).toBe('ELEVATED');
  });
});
