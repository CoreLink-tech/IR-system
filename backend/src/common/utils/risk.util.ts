export function riskThresholds() {
  return {
    suspicious: Number(process.env.RISK_LEVEL_SUSPICIOUS ?? 30),
    high: Number(process.env.RISK_LEVEL_HIGH ?? 60),
    critical: Number(process.env.RISK_LEVEL_CRITICAL ?? 80),
  };
}

export function riskLevelFor(score: number): 'NORMAL' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' {
  const t = riskThresholds();
  if (score >= t.critical) return 'CRITICAL';
  if (score >= t.high) return 'HIGH';
  if (score >= t.suspicious) return 'SUSPICIOUS';
  return 'NORMAL';
}

export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}
