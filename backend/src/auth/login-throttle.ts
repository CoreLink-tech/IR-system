import { createHash } from 'crypto';
import { inCidr, isInternalAddress, normalizeIp, parseTrustedProxies } from '../common/utils/ip.util';

/**
 * Lockout settings. After THRESHOLD wrong attempts in a row the account is locked for BASE seconds, and every
 * further wrong attempt doubles that, up to MAX. A lock always expires; there is no permanent lock.
 */
export interface LockoutConfig {
  threshold: number;
  baseSeconds: number;
  maxSeconds: number;
  /** Failures are forgotten after this long without a new one. Must be longer than MAX. */
  resetMinutes: number;
  /** Networks that are never locked out (for example the office VPN). Addresses, CIDR blocks or "private". */
  exemptNetworks: string[];
}

export function loadLockoutConfig(env: NodeJS.ProcessEnv = process.env): { config: LockoutConfig; errors: string[] } {
  const errors: string[] = [];
  const num = (name: string, def: number, min: number, max: number) => {
    const raw = env[name];
    if (raw === undefined || raw.trim() === '') return def;
    if (!/^\d+$/.test(raw.trim())) { errors.push(`${name} must be a whole number, got "${raw}".`); return def; }
    const n = Number(raw.trim());
    if (n < min || n > max) { errors.push(`${name} must be between ${min} and ${max}, got ${n}.`); return def; }
    return n;
  };
  const config: LockoutConfig = {
    threshold: num('LOCKOUT_THRESHOLD', 5, 3, 20),
    baseSeconds: num('LOCKOUT_BASE_SECONDS', 30, 5, 3600),
    maxSeconds: num('LOCKOUT_MAX_SECONDS', 900, 30, 86400),
    resetMinutes: num('LOCKOUT_RESET_MINUTES', 60, 5, 10080),
    exemptNetworks: parseTrustedProxies(env.LOCKOUT_EXEMPT_NETWORKS),
  };
  if (config.maxSeconds < config.baseSeconds) errors.push('LOCKOUT_MAX_SECONDS must not be smaller than LOCKOUT_BASE_SECONDS.');
  if (config.resetMinutes * 60 <= config.maxSeconds) errors.push('LOCKOUT_RESET_MINUTES must be longer than LOCKOUT_MAX_SECONDS, or a lock could be forgotten before it ends.');
  for (const e of config.exemptNetworks) {
    if (e.toLowerCase() === 'private') continue;
    const [addr, bits] = e.split('/');
    if (!normalizeIp(addr) || (bits !== undefined && !/^\d{1,3}$/.test(bits))) errors.push(`LOCKOUT_EXEMPT_NETWORKS entry "${e}" is not an address, a CIDR block or the word private.`);
  }
  return { config, errors };
}

/** The key under which attempts for an email address are counted. The address itself is never stored. */
export function loginKey(email: string): string {
  return 'login:' + createHash('sha256').update(String(email).trim().toLowerCase()).digest('hex');
}

/** True when sign-ins from this address are never locked out. */
export function isExempt(ip: string | undefined, cfg: LockoutConfig): boolean {
  const addr = normalizeIp(ip);
  if (!addr || cfg.exemptNetworks.length === 0) return false;
  return cfg.exemptNetworks.some((e) => (e.toLowerCase() === 'private' ? isInternalAddress(addr) : inCidr(addr, e)));
}

export interface ThrottleState { failures: number; lockedUntil: Date | null; lastFailureAt: Date }

export interface Decision {
  /** False when the account is locked: the password must not even be checked. */
  allowed: boolean;
  /** State to store. Unchanged when the attempt was refused, so attempts during a lock never extend it. */
  state: ThrottleState | null;
  /** Seconds until another attempt is possible (0 when allowed and not locked by this attempt). */
  retryAfterSeconds: number;
  /** True when THIS attempt started a lock. The attempt itself is still allowed and checked. */
  lockedNow: boolean;
}

/**
 * The whole lockout rule as a pure function, shared by the database service and the tests.
 *
 * Each attempt is counted BEFORE the password is checked, and the lock it triggers is set at the same moment.
 * So even many attempts arriving at once cannot get more than THRESHOLD password checks per lock window.
 * If the password turns out right, the caller deletes the state.
 */
export function decide(prev: ThrottleState | null, now: Date, cfg: LockoutConfig): Decision {
  if (prev?.lockedUntil && prev.lockedUntil.getTime() > now.getTime()) {
    return { allowed: false, state: prev, retryAfterSeconds: Math.max(1, Math.ceil((prev.lockedUntil.getTime() - now.getTime()) / 1000)), lockedNow: false };
  }
  const forgotten = !prev || now.getTime() - prev.lastFailureAt.getTime() > cfg.resetMinutes * 60_000;
  const failures = (forgotten ? 0 : prev!.failures) + 1;
  let lockedUntil: Date | null = null;
  let retryAfterSeconds = 0;
  if (failures >= cfg.threshold) {
    retryAfterSeconds = Math.min(cfg.maxSeconds, cfg.baseSeconds * 2 ** Math.min(failures - cfg.threshold, 30));
    lockedUntil = new Date(now.getTime() + retryAfterSeconds * 1000);
  }
  return { allowed: true, state: { failures, lockedUntil, lastFailureAt: now }, retryAfterSeconds, lockedNow: lockedUntil !== null };
}

/** "30 seconds", "1 minute", "5 minutes": how long to wait, in words a person can use. */
export function waitText(seconds: number): string {
  if (seconds < 90) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const m = Math.ceil(seconds / 60);
  return `${m} minute${m === 1 ? '' : 's'}`;
}
