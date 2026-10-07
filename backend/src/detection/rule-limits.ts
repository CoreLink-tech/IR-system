import { BadRequestException } from '@nestjs/common';
import { BUILT_IN_RULES } from './rules';

/** The range an administrator may set for one setting. Whole numbers only. */
export interface KeyLimit { min: number; max: number }

/**
 * Allowed ranges for every editable detection setting. A rule's thresholds decide what counts
 * as an attack, so they can be changed, but only inside sensible bounds, and only through this
 * list. A setting that is not listed here cannot be edited.
 */
export const KEY_LIMITS: Record<string, KeyLimit> = {
  threshold: { min: 1, max: 1000 },
  incidentAt: { min: 1, max: 1000 },
  riskPerAttempt: { min: 1, max: 100 },
  maxRisk: { min: 1, max: 100 },
  riskDelta: { min: 1, max: 100 },
  torRisk: { min: 0, max: 100 },
  proxyRisk: { min: 0, max: 100 },
  vpnRisk: { min: 0, max: 100 },
  distinctUsersThreshold: { min: 1, max: 1000 },
  distinctIpsThreshold: { min: 1, max: 1000 },
  failedLoginsThreshold: { min: 1, max: 10000 },
  minFailedLogins: { min: 1, max: 1000 },
  criticalFailedLogins: { min: 1, max: 1000 },
  criticalFromIps: { min: 1, max: 1000 },
  criticalAtIps: { min: 1, max: 10000 },
};

/**
 * Settings that are shown but cannot be edited. The detector counts activity over a fixed
 * 10 minute window, so a "window" value in a rule's settings does not change what is counted;
 * letting it be edited would suggest a change that does nothing.
 */
export const READ_ONLY_KEYS = new Set(['windowMinutes']);

/** Pairs where the first must not exceed the second, or the rule would contradict itself. */
const ORDERED: Array<[string, string, string]> = [
  ['riskPerAttempt', 'maxRisk', 'The risk added per attempt cannot be higher than the maximum risk.'],
  ['minFailedLogins', 'criticalFailedLogins', 'The critical number of failed logins cannot be lower than the number that triggers the rule.'],
  ['distinctIpsThreshold', 'criticalAtIps', 'The critical number of addresses cannot be lower than the number that triggers the rule.'],
  ['threshold', 'incidentAt', 'An incident cannot be opened before the rule itself triggers.'],
];

export function defaultConfigFor(code: string): Record<string, number> | undefined {
  return BUILT_IN_RULES.find((r) => r.code === code)?.defaultConfig as Record<string, number> | undefined;
}

export function limitsFor(code: string): Record<string, KeyLimit & { editable: boolean }> {
  const out: Record<string, KeyLimit & { editable: boolean }> = {};
  for (const key of Object.keys(defaultConfigFor(code) ?? {})) {
    const lim = KEY_LIMITS[key];
    out[key] = READ_ONLY_KEYS.has(key) || !lim
      ? { min: 0, max: 0, editable: false }
      : { ...lim, editable: true };
  }
  return out;
}

/**
 * Applies a partial change to a rule's current settings and returns the full result, or
 * throws a 400 listing every problem. The full set is always stored, because the detector
 * reads the whole object and a missing key would silently turn a comparison into "never".
 */
export function validateRuleConfig(
  code: string, current: Record<string, any>, change: Record<string, unknown>,
): Record<string, number> {
  const defaults = defaultConfigFor(code);
  if (!defaults) throw new BadRequestException('Unknown rule');
  const problems: string[] = [];
  const merged: Record<string, number> = { ...defaults, ...(current as any) };

  for (const key of Object.keys(change)) {
    const value = change[key];
    if (!Object.prototype.hasOwnProperty.call(defaults, key)) { problems.push(`"${key}" is not a setting of this rule`); continue; }
    if (READ_ONLY_KEYS.has(key)) {
      if (value !== merged[key]) problems.push(`"${key}" is fixed and cannot be changed`);
      continue;
    }
    const lim = KEY_LIMITS[key];
    if (typeof value !== 'number' || !Number.isInteger(value)) { problems.push(`"${key}" must be a whole number`); continue; }
    if (value < lim.min || value > lim.max) { problems.push(`"${key}" must be between ${lim.min} and ${lim.max}`); continue; }
    merged[key] = value;
  }
  if (problems.length === 0) {
    for (const [lower, upper, message] of ORDERED) {
      if (lower in merged && upper in merged && merged[lower] > merged[upper]) problems.push(message);
    }
  }
  if (problems.length) throw new BadRequestException(problems);
  return merged;
}
