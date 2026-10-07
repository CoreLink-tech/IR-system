import { BadRequestException, NotFoundException } from '@nestjs/common';
import { BUILT_IN_RULES } from '../src/detection/rules';
import { KEY_LIMITS, READ_ONLY_KEYS, defaultConfigFor, limitsFor, validateRuleConfig } from '../src/detection/rule-limits';
import { RulesService } from '../src/rules/rules.service';
import { NARRATIVES } from '../src/reports/rule-narratives';

const actor = { type: 'USER' as const, id: 'u1', label: 'sec@pishon.ng', ip: '203.0.113.5', userAgent: 'jest', requestId: 'r1' };

describe('rule limits cover every built-in rule', () => {
  it('has a range for every editable setting of every rule, and the defaults sit inside it', () => {
    for (const rule of BUILT_IN_RULES) {
      for (const [key, value] of Object.entries(rule.defaultConfig)) {
        if (READ_ONLY_KEYS.has(key)) continue;
        const lim = KEY_LIMITS[key];
        expect([rule.code, key, !!lim]).toEqual([rule.code, key, true]);
        expect(value).toBeGreaterThanOrEqual(lim.min);
        expect(value).toBeLessThanOrEqual(lim.max);
        expect(Number.isInteger(value)).toBe(true);
      }
    }
  });
  it('accepts the defaults unchanged for every rule (the ordering checks hold for them)', () => {
    for (const rule of BUILT_IN_RULES) expect(validateRuleConfig(rule.code, rule.defaultConfig, rule.defaultConfig)).toEqual(rule.defaultConfig);
  });
  it('marks the fixed detection window as read-only and the thresholds as editable', () => {
    const l = limitsFor('brute_force_login');
    expect(l.windowMinutes.editable).toBe(false);
    expect(l.threshold).toEqual({ min: 1, max: 1000, editable: true });
  });
});

/** The text of every problem a rejected change reported. */
function problems(fn: () => unknown): string {
  try { fn(); } catch (e: any) { return [].concat(e.getResponse().message).join(' | '); }
  return '';
}

describe('validateRuleConfig', () => {
  const cur = () => ({ ...defaultConfigFor('brute_force_login')! });
  it('merges a partial change over the current settings and returns the full set', () => {
    expect(validateRuleConfig('brute_force_login', cur(), { threshold: 9, incidentAt: 9 })).toEqual({ ...cur(), threshold: 9, incidentAt: 9 });
  });
  it('fills in a setting missing from an old stored row, so the detector never sees undefined', () => {
    const merged = validateRuleConfig('brute_force_login', { threshold: 5 }, { maxRisk: 60 });
    expect(Object.keys(merged).sort()).toEqual(Object.keys(cur()).sort());
  });
  it('rejects values outside the range, fractions, strings, null and NaN, naming each problem', () => {
    for (const bad of [0, -1, 1001, 2.5, '7', null, NaN, Infinity, true, [], {}]) {
      expect(() => validateRuleConfig('brute_force_login', cur(), { threshold: bad as any })).toThrow(BadRequestException);
    }
    try { validateRuleConfig('brute_force_login', cur(), { threshold: 0, maxRisk: 500 }); } catch (e: any) {
      expect(e.getResponse().message).toHaveLength(2);
    }
  });
  it('rejects unknown settings, including prototype tricks', () => {
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), { nope: 1 }))).toMatch(/not a setting/);
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), JSON.parse('{"__proto__":{"threshold":1}}')))).toMatch(/not a setting/);
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), { constructor: 1 }))).toMatch(/not a setting/);
    expect(({} as any).threshold).toBeUndefined();
  });
  it('refuses to change the fixed window, but accepts it being sent back unchanged', () => {
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), { windowMinutes: 60 }))).toMatch(/fixed/);
    expect(validateRuleConfig('brute_force_login', cur(), { windowMinutes: 10 })).toEqual(cur());
  });
  it('refuses combinations that contradict each other', () => {
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), { riskPerAttempt: 90, maxRisk: 50 }))).toMatch(/risk added per attempt/);
    expect(problems(() => validateRuleConfig('brute_force_login', cur(), { threshold: 20 }))).toMatch(/incident cannot be opened/);
    expect(problems(() => validateRuleConfig('possible_account_takeover', defaultConfigFor('possible_account_takeover')!, { criticalFailedLogins: 2 }))).toMatch(/critical number of failed logins/);
    expect(problems(() => validateRuleConfig('distributed_login_attack', defaultConfigFor('distributed_login_attack')!, { criticalAtIps: 5 }))).toMatch(/critical number of addresses/);
  });
  it('rejects an unknown rule', () => {
    expect(() => validateRuleConfig('nope', {}, {})).toThrow(BadRequestException);
  });
});

function make(rows: any[] = []) {
  const prisma: any = {
    securityRule: {
      findMany: async () => rows.map((r) => ({ ...r })),
      findUnique: async ({ where }: any) => { const r = rows.find((x) => x.code === where.code); return r ? { ...r } : null; },
      upsert: jest.fn(async ({ where, create }: any) => { let r = rows.find((x) => x.code === where.code); if (!r) { r = { ...create }; rows.push(r); } return { ...r }; }),
      update: jest.fn(async ({ where, data }: any) => Object.assign(rows.find((x) => x.code === where.code), data)),
    },
  };
  const audit = { log: jest.fn(async () => undefined) };
  return { svc: new RulesService(prisma, audit as any), prisma, audit, rows };
}
const row = (code: string, over: any = {}) => {
  const d = BUILT_IN_RULES.find((r) => r.code === code)!;
  return { code, name: d.name, description: d.description, priority: d.priority, isEnabled: true, config: { ...d.defaultConfig }, ...over };
};

describe('RulesService', () => {
  it('lists every built-in rule in priority order with plain titles, defaults and limits, creating missing rows', async () => {
    const m = make([row('brute_force_login')]);
    const list = await m.svc.list();
    expect(list).toHaveLength(BUILT_IN_RULES.length);
    expect(list.map((r: any) => r.priority)).toEqual([...list.map((r: any) => r.priority)].sort((a, b) => a - b));
    const bf: any = list.find((r: any) => r.code === 'brute_force_login');
    expect(bf.title).toBe(NARRATIVES.brute_force_login.title);
    expect(bf.isDefault).toBe(true);
    expect(bf.defaultConfig).toEqual(defaultConfigFor('brute_force_login'));
    expect(bf.limits.threshold.editable).toBe(true);
    expect(bf.whyItMatters).toBeTruthy();
  });
  it('flags a rule whose settings differ from the defaults', async () => {
    const m = make(BUILT_IN_RULES.map((r) => row(r.code, r.code === 'brute_force_login' ? { config: { ...r.defaultConfig, threshold: 8 } } : {})));
    const list: any[] = await m.svc.list();
    expect(list.find((r) => r.code === 'brute_force_login').isDefault).toBe(false);
    expect(list.find((r) => r.code === 'high_request_rate').isDefault).toBe(true);
  });
  it('changes thresholds, stores the full set, and audits old and new values with the reason', async () => {
    const m = make([row('brute_force_login')]);
    const r: any = await m.svc.update('brute_force_login', { config: { threshold: 8, incidentAt: 8 }, reason: 'too noisy' }, actor);
    expect(r.config).toMatchObject({ threshold: 8, incidentAt: 8, windowMinutes: 10 });
    expect(m.prisma.securityRule.update.mock.calls[0][0].data.config).toHaveProperty('maxRisk');
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'rule.update', targetType: 'rule', targetId: 'brute_force_login', actorId: 'u1', result: 'SUCCESS',
      metadata: {
        old: { isEnabled: true, config: expect.objectContaining({ threshold: 5 }) },
        new: { isEnabled: true, config: expect.objectContaining({ threshold: 8 }) },
        reason: 'too noisy',
      },
    }));
  });
  it('switches a rule off and back on, audited each time', async () => {
    const m = make([row('brute_force_login')]);
    expect(((await m.svc.update('brute_force_login', { isEnabled: false }, actor)) as any).isEnabled).toBe(false);
    expect(((await m.svc.update('brute_force_login', { isEnabled: true }, actor)) as any).isEnabled).toBe(true);
    expect(m.audit.log).toHaveBeenCalledTimes(2);
  });
  it('writes nothing and audits nothing when nothing changes', async () => {
    const m = make([row('brute_force_login')]);
    await m.svc.update('brute_force_login', { isEnabled: true, config: { threshold: 5 } }, actor);
    expect(m.prisma.securityRule.update).not.toHaveBeenCalled();
    expect(m.audit.log).not.toHaveBeenCalled();
  });
  it('does not save or audit an invalid change', async () => {
    const m = make([row('brute_force_login')]);
    await expect(m.svc.update('brute_force_login', { config: { threshold: 0 } }, actor)).rejects.toBeInstanceOf(BadRequestException);
    expect(m.prisma.securityRule.update).not.toHaveBeenCalled();
    expect(m.audit.log).not.toHaveBeenCalled();
  });
  it('answers 404 for an unknown rule and 400 for an empty change', async () => {
    const m = make([row('brute_force_login')]);
    await expect(m.svc.update('nope', { isEnabled: false }, actor)).rejects.toBeInstanceOf(NotFoundException);
    await expect(m.svc.reset('nope', undefined, actor)).rejects.toBeInstanceOf(NotFoundException);
    await expect(m.svc.update('brute_force_login', {}, actor)).rejects.toBeInstanceOf(BadRequestException);
  });
  it('creates the row on first edit when a rule has never been stored', async () => {
    const m = make([]);
    const r: any = await m.svc.update('high_request_rate', { config: { threshold: 100 } }, actor);
    expect(r.config.threshold).toBe(100);
    expect(m.rows).toHaveLength(1);
  });
  it('resets thresholds to the defaults, keeps the on/off state, and audits it', async () => {
    const m = make([row('brute_force_login', { isEnabled: false, config: { ...defaultConfigFor('brute_force_login'), threshold: 9, incidentAt: 9 } })]);
    const r: any = await m.svc.reset('brute_force_login', 'back to normal', actor);
    expect(r.config).toEqual(defaultConfigFor('brute_force_login'));
    expect(r.isDefault).toBe(true);
    expect(r.isEnabled).toBe(false);
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'rule.reset', metadata: expect.objectContaining({ reason: 'back to normal' }) }));
  });
  it('does nothing when reset a rule that is already at its defaults', async () => {
    const m = make([row('brute_force_login')]);
    await m.svc.reset('brute_force_login', undefined, actor);
    expect(m.audit.log).not.toHaveBeenCalled();
  });
});
