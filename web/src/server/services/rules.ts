import { eq } from 'drizzle-orm';
import { db } from '@/server/db/client';
import { detectionRules } from '@/server/db/schema';

export type RuleDef = {
  code: string;
  title: string;
  description: string;
  defaultEnabled: boolean;
  defaultPriority: number;
  defaultConfig: Record<string, number>;
  limits: Record<string, { min: number; max: number }>;
};

export const RULE_CATALOG: RuleDef[] = [
  {
    code: 'login_failed',
    title: 'Failed sign-in',
    description: 'Raises risk when a login_failed event is received.',
    defaultEnabled: true,
    defaultPriority: 100,
    defaultConfig: { baseScore: 25 },
    limits: { baseScore: { min: 0, max: 100 } },
  },
  {
    code: 'suspicious_request',
    title: 'Suspicious request',
    description: 'Scoring for suspicious_request events.',
    defaultEnabled: true,
    defaultPriority: 90,
    defaultConfig: { baseScore: 40 },
    limits: { baseScore: { min: 0, max: 100 } },
  },
  {
    code: 'rate_limit',
    title: 'Rate limit exceeded',
    description: 'Scoring for rate_limit_exceeded events.',
    defaultEnabled: true,
    defaultPriority: 95,
    defaultConfig: { baseScore: 30 },
    limits: { baseScore: { min: 0, max: 100 } },
  },
  {
    code: 'payment',
    title: 'Payment security',
    description: 'Scoring for payment_security_event.',
    defaultEnabled: true,
    defaultPriority: 80,
    defaultConfig: { baseScore: 50 },
    limits: { baseScore: { min: 0, max: 100 } },
  },
  {
    code: 'admin_access',
    title: 'Admin access',
    description: 'Scoring for admin_access events.',
    defaultEnabled: true,
    defaultPriority: 110,
    defaultConfig: { baseScore: 15 },
    limits: { baseScore: { min: 0, max: 100 } },
  },
  {
    code: 'auto_block',
    title: 'Automatic block threshold',
    description: 'Block the source IP when risk score reaches this value (private/allowlisted IPs never blocked).',
    defaultEnabled: true,
    defaultPriority: 10,
    defaultConfig: { threshold: 85, blockMinutes: 60 },
    limits: { threshold: { min: 50, max: 100 }, blockMinutes: { min: 5, max: 10080 } },
  },
];

export async function listRules() {
  const rows = await db.select().from(detectionRules);
  const byCode = new Map(rows.map((r) => [r.code, r]));
  return RULE_CATALOG.map((def) => {
    const row = byCode.get(def.code);
    const config = row?.config ? (JSON.parse(row.config) as Record<string, number>) : { ...def.defaultConfig };
    return {
      code: def.code,
      title: def.title,
      description: def.description,
      isEnabled: row ? !!row.isEnabled : def.defaultEnabled,
      priority: row?.priority ?? def.defaultPriority,
      config,
      defaultConfig: def.defaultConfig,
      limits: def.limits,
      isDefault: !row,
      updatedAt: row?.updatedAt?.toISOString() ?? null,
    };
  });
}

export async function getRuleRuntime(): Promise<
  Record<string, { enabled: boolean; config: Record<string, number> }>
> {
  const listed = await listRules();
  const out: Record<string, { enabled: boolean; config: Record<string, number> }> = {};
  for (const r of listed) out[r.code] = { enabled: r.isEnabled, config: r.config };
  return out;
}

export async function updateRule(
  code: string,
  patch: { isEnabled?: boolean; config?: Record<string, number> },
) {
  const def = RULE_CATALOG.find((r) => r.code === code);
  if (!def) throw Object.assign(new Error('Unknown rule'), { status: 404, code: 'not_found' });
  if (patch.config) {
    for (const [k, v] of Object.entries(patch.config)) {
      const lim = def.limits[k];
      if (!lim) throw Object.assign(new Error(`Unknown config key ${k}`), { status: 400, code: 'invalid_body' });
      if (typeof v !== 'number' || v < lim.min || v > lim.max) {
        throw Object.assign(new Error(`${k} out of range`), { status: 400, code: 'invalid_body' });
      }
    }
  }
  const existing = await db.select().from(detectionRules).where(eq(detectionRules.code, code)).limit(1);
  const config = {
    ...def.defaultConfig,
    ...(existing[0]?.config ? JSON.parse(existing[0].config) : {}),
    ...(patch.config || {}),
  };
  const isEnabled = patch.isEnabled ?? (existing[0] ? !!existing[0].isEnabled : def.defaultEnabled);
  if (existing[0]) {
    await db
      .update(detectionRules)
      .set({ isEnabled, config: JSON.stringify(config), updatedAt: new Date() })
      .where(eq(detectionRules.code, code));
  } else {
    await db.insert(detectionRules).values({
      code,
      isEnabled,
      priority: def.defaultPriority,
      config: JSON.stringify(config),
      updatedAt: new Date(),
    });
  }
  return (await listRules()).find((r) => r.code === code)!;
}
