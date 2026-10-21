import { Decision, ThrottleState, decide, isExempt, loadLockoutConfig, loginKey } from '../src/auth/login-throttle';
import { waitText } from '../src/auth/auth.service';
import { validateConfig } from '../src/config/validate-config';

const cfg = loadLockoutConfig({}).config;
const T0 = new Date('2026-10-20T10:00:00.000Z');
const at = (s: number) => new Date(T0.getTime() + s * 1000);
const run = (n: number, from: ThrottleState | null = null, start = 0): { last: Decision; state: ThrottleState | null } => {
  let state = from; let last!: Decision;
  for (let i = 0; i < n; i++) { last = decide(state, at(start), cfg); if (last.allowed) state = last.state; }
  return { last, state };
};

describe('lockout rule (decide)', () => {
  it('allows the first attempts without a lock, counting each', () => {
    let s: ThrottleState | null = null;
    for (let i = 1; i <= 4; i++) { const d = decide(s, at(0), cfg); expect(d).toMatchObject({ allowed: true, lockedNow: false, retryAfterSeconds: 0 }); expect(d.state!.failures).toBe(i); s = d.state; }
  });
  it('the fifth attempt is still checked, but starts a 30 second lock', () => {
    const { last } = run(5);
    expect(last).toMatchObject({ allowed: true, lockedNow: true, retryAfterSeconds: 30 });
    expect(last.state!.lockedUntil!.getTime()).toBe(at(30).getTime());
  });
  it('refuses while locked and returns the state unchanged, with the time left', () => {
    const { state } = run(5);
    const d = decide(state, at(10), cfg);
    expect(d).toMatchObject({ allowed: false, lockedNow: false, retryAfterSeconds: 20 });
    expect(d.state).toBe(state);
  });
  it('rounds the time left up, and never says zero', () => { const { state } = run(5); expect(decide(state, at(29.2), cfg).retryAfterSeconds).toBe(1); expect(decide(state, at(29.999), cfg).retryAfterSeconds).toBe(1); });
  it('allows one more attempt the moment the lock ends, with a longer lock if it is wrong again', () => {
    const { state } = run(5);
    const d = decide(state, at(30), cfg);
    expect(d).toMatchObject({ allowed: true, lockedNow: true, retryAfterSeconds: 60 });
  });
  it('doubles up to the cap and stays there', () => {
    const waits: number[] = []; let state: ThrottleState | null = null; let t = 0;
    for (let i = 0; i < 14; i++) { const d = decide(state, at(t), cfg); state = d.state; if (d.lockedNow) { waits.push(d.retryAfterSeconds); t += d.retryAfterSeconds; } }
    expect(waits).toEqual([30, 60, 120, 240, 480, 900, 900, 900, 900, 900]);
  });
  it('never overflows however many failures there are', () => {
    const d = decide({ failures: 10_000_000, lockedUntil: null, lastFailureAt: at(0) }, at(1), cfg);
    expect(d.retryAfterSeconds).toBe(900); expect(Number.isFinite(d.state!.lockedUntil!.getTime())).toBe(true);
  });
  it('forgets failures after the quiet period (60 minutes by default)', () => {
    const { state } = run(4);
    expect(decide(state, at(60 * 60), cfg).state!.failures).toBe(5);       // exactly an hour: still remembered
    expect(decide(state, at(60 * 60 + 1), cfg).state!.failures).toBe(1);   // after it: starts again
  });
  it('a lock ends by itself: there is no state in which it lasts forever', () => {
    const { state } = run(40);
    const far = new Date(state!.lockedUntil!.getTime() + 1);
    expect(decide(state, far, cfg).allowed).toBe(true);
    expect(state!.lockedUntil!.getTime() - at(0).getTime()).toBeLessThanOrEqual(900_000);
  });
  it('respects other settings', () => {
    const c = loadLockoutConfig({ LOCKOUT_THRESHOLD: '3', LOCKOUT_BASE_SECONDS: '10', LOCKOUT_MAX_SECONDS: '40' } as any).config;
    let s: ThrottleState | null = null; const waits: number[] = [];
    for (let i = 0; i < 6; i++) { const d = decide(s, at(1000 + i * 100), c); s = d.state; if (d.lockedNow) waits.push(d.retryAfterSeconds); }
    expect(waits).toEqual([10, 20, 40, 40]);
  });
});

describe('lockout settings', () => {
  it('have the defaults', () => { expect(loadLockoutConfig({}).config).toEqual({ threshold: 5, baseSeconds: 30, maxSeconds: 900, resetMinutes: 60, exemptNetworks: [] }); });
  it('refuse silly values with a sentence each', () => {
    const { errors } = loadLockoutConfig({ LOCKOUT_THRESHOLD: '1', LOCKOUT_BASE_SECONDS: 'fast', LOCKOUT_MAX_SECONDS: '10', LOCKOUT_RESET_MINUTES: '2', LOCKOUT_EXEMPT_NETWORKS: 'banana, 10.0.0.0/8' } as any);
    expect(errors.join(' | ')).toMatch(/LOCKOUT_THRESHOLD must be between 3 and 20/);
    expect(errors.join(' | ')).toMatch(/LOCKOUT_BASE_SECONDS must be a whole number/);
    expect(errors.join(' | ')).toMatch(/LOCKOUT_MAX_SECONDS must be between 30/);
    expect(errors.join(' | ')).toMatch(/"banana"/);
  });
  it('refuse a reset period shorter than the longest lock (a lock could be forgotten early)', () => {
    expect(loadLockoutConfig({ LOCKOUT_RESET_MINUTES: '10', LOCKOUT_MAX_SECONDS: '900' } as any).errors.join()).toMatch(/longer than LOCKOUT_MAX_SECONDS/);
  });
  it('stop the API from starting', () => {
    const env: any = { NODE_ENV: 'development', JWT_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), API_KEY_HASH_PEPPER: 'c'.repeat(20), DATABASE_URL: 'mysql://u:p@h/d', LOCKOUT_THRESHOLD: '99' };
    expect(validateConfig(env).errors.join()).toContain('LOCKOUT_THRESHOLD');
  });
});

describe('trusted networks', () => {
  const c = (n: string) => loadLockoutConfig({ LOCKOUT_EXEMPT_NETWORKS: n } as any).config;
  it('match addresses, blocks and the word private', () => {
    expect(isExempt('10.4.5.6', c('10.0.0.0/8'))).toBe(true);
    expect(isExempt('11.4.5.6', c('10.0.0.0/8'))).toBe(false);
    expect(isExempt('192.168.1.9', c('private'))).toBe(true);
    expect(isExempt('203.0.113.9', c('private'))).toBe(false);
    expect(isExempt('203.0.113.9', c('203.0.113.9'))).toBe(true);
    expect(isExempt('2001:db8::5', c('2001:db8::/32'))).toBe(true);
  });
  it('are empty by default, and an unknown address is never exempt', () => {
    expect(isExempt('10.4.5.6', c(''))).toBe(false);
    expect(isExempt(undefined, c('10.0.0.0/8'))).toBe(false);
    expect(isExempt('not-an-address', c('private'))).toBe(false);
  });
});

describe('keys and wait text', () => {
  it('hash the lower-cased, trimmed email', () => {
    expect(loginKey('A@B.com')).toBe(loginKey(' a@b.COM '));
    expect(loginKey('a@b.com')).not.toBe(loginKey('a@c.com'));
    expect(loginKey('a@b.com')).toMatch(/^login:[0-9a-f]{64}$/);
  });
  it('wait text is plain', () => {
    expect([1, 30, 89, 90, 120, 480, 900].map(waitText)).toEqual(['1 second', '30 seconds', '89 seconds', '2 minutes', '2 minutes', '8 minutes', '15 minutes']);
  });
});
