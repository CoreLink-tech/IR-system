import { riskLevelFor, clampScore } from '../src/common/utils/risk.util';

describe('riskLevelFor', () => {
  const original = { ...process.env };

  beforeAll(() => {
    process.env.RISK_LEVEL_SUSPICIOUS = '30';
    process.env.RISK_LEVEL_HIGH = '60';
    process.env.RISK_LEVEL_CRITICAL = '80';
  });

  afterAll(() => {
    process.env.RISK_LEVEL_SUSPICIOUS = original.RISK_LEVEL_SUSPICIOUS;
    process.env.RISK_LEVEL_HIGH = original.RISK_LEVEL_HIGH;
    process.env.RISK_LEVEL_CRITICAL = original.RISK_LEVEL_CRITICAL;
  });

  it('returns NORMAL below the suspicious threshold', () => {
    expect(riskLevelFor(0)).toBe('NORMAL');
    expect(riskLevelFor(29)).toBe('NORMAL');
  });

  it('returns SUSPICIOUS in the suspicious range', () => {
    expect(riskLevelFor(30)).toBe('SUSPICIOUS');
    expect(riskLevelFor(59)).toBe('SUSPICIOUS');
  });

  it('returns HIGH in the high range', () => {
    expect(riskLevelFor(60)).toBe('HIGH');
    expect(riskLevelFor(79)).toBe('HIGH');
  });

  it('returns CRITICAL at the critical threshold and above', () => {
    expect(riskLevelFor(80)).toBe('CRITICAL');
    expect(riskLevelFor(100)).toBe('CRITICAL');
  });
});

describe('clampScore', () => {
  it('clamps below zero', () => expect(clampScore(-10)).toBe(0));
  it('clamps above 100', () => expect(clampScore(150)).toBe(100));
  it('rounds', () => expect(clampScore(42.6)).toBe(43));
});
