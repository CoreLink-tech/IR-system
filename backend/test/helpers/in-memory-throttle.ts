import { LockoutConfig, ThrottleState, decide, loadLockoutConfig } from '../../src/auth/login-throttle';

/**
 * The same lockout rule (decide) as the database service, with the state in memory and a clock the test
 * controls. The database behaviour, including simultaneous attempts, is tested on a real database in
 * test/login-throttle-db.spec.ts.
 */
export class InMemoryThrottle {
  store = new Map<string, ThrottleState>();
  now = new Date('2026-10-20T10:00:00.000Z');
  cfg: LockoutConfig;
  constructor(env: Record<string, string> = {}) { this.cfg = loadLockoutConfig(env as any).config; }
  advance(seconds: number) { this.now = new Date(this.now.getTime() + seconds * 1000); }
  config() { return this.cfg; }
  async reserve(key: string) {
    const d = decide(this.store.get(key) ?? null, this.now, this.cfg);
    if (d.allowed && d.state) this.store.set(key, d.state);
    return d;
  }
  async reset(key: string) { this.store.delete(key); }
  async lockedUntil(keys: string[]) {
    const m = new Map<string, Date>();
    for (const k of keys) { const s = this.store.get(k); if (s?.lockedUntil && s.lockedUntil > this.now) m.set(k, s.lockedUntil); }
    return m;
  }
}
