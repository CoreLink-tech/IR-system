import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { ActorContext } from '../common/decorators/current-actor.decorator';
import { AUDIT_ACTIONS } from '../common/constants';
import { BUILT_IN_RULES } from '../detection/rules';
import { defaultConfigFor, limitsFor, validateRuleConfig } from '../detection/rule-limits';
import { NARRATIVES, ruleTitle } from '../reports/rule-narratives';

const same = (a: unknown, b: unknown) => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
function sortKeys(v: any): any {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return v;
  return Object.keys(v).sort().reduce((o: any, k) => { o[k] = v[k]; return o; }, {});
}

/** Reading and tuning the detection rules. Changes take effect on the next event. */
@Injectable()
export class RulesService {
  constructor(private readonly prisma: PrismaService, private readonly audit: AuditService) {}

  async list() {
    const rows = await this.prisma.securityRule.findMany({ orderBy: { priority: 'asc' } });
    const have = new Set(rows.map((r: any) => r.code));
    for (const def of BUILT_IN_RULES.filter((d) => !have.has(d.code))) rows.push(await this.createRow(def.code));
    rows.sort((a: any, b: any) => a.priority - b.priority);
    return rows.filter((r: any) => defaultConfigFor(r.code)).map((r: any) => this.present(r));
  }

  async update(code: string, dto: { isEnabled?: boolean; config?: Record<string, unknown>; reason?: string }, actor: ActorContext) {
    if (dto.isEnabled === undefined && dto.config === undefined) throw new BadRequestException('Nothing to change');
    const row = await this.row(code);
    const nextConfig = dto.config ? validateRuleConfig(code, row.config as any, dto.config) : (row.config as any);
    const nextEnabled = dto.isEnabled ?? row.isEnabled;
    if (nextEnabled === row.isEnabled && same(nextConfig, row.config)) return this.present(row);
    const updated = await this.prisma.securityRule.update({ where: { code }, data: { isEnabled: nextEnabled, config: nextConfig as any } });
    await this.record(AUDIT_ACTIONS.RULE_UPDATE, code, row, updated, dto.reason, actor);
    return this.present(updated);
  }

  /** Puts a rule back to its built-in thresholds. Whether it is on or off is not touched. */
  async reset(code: string, reason: string | undefined, actor: ActorContext) {
    const row = await this.row(code);
    const defaults = defaultConfigFor(code)!;
    if (same(defaults, row.config)) return this.present(row);
    const updated = await this.prisma.securityRule.update({ where: { code }, data: { config: defaults as any } });
    await this.record(AUDIT_ACTIONS.RULE_RESET, code, row, updated, reason, actor);
    return this.present(updated);
  }

  private async row(code: string) {
    if (!defaultConfigFor(code)) throw new NotFoundException('Rule not found');
    return (await this.prisma.securityRule.findUnique({ where: { code } })) ?? this.createRow(code);
  }

  private createRow(code: string) {
    const def = BUILT_IN_RULES.find((d) => d.code === code)!;
    return this.prisma.securityRule.upsert({
      where: { code },
      update: {},
      create: { code, name: def.name, description: def.description, priority: def.priority, isEnabled: true, config: def.defaultConfig as any },
    });
  }

  private record(action: string, code: string, before: any, after: any, reason: string | undefined, actor: ActorContext) {
    return this.audit.log({
      requestId: actor.requestId, actorType: 'USER', actorId: actor.id, actorLabel: actor.label,
      action, targetType: 'rule', targetId: code, result: 'SUCCESS',
      ipAddress: actor.ip, userAgent: actor.userAgent,
      metadata: {
        old: { isEnabled: before.isEnabled, config: before.config },
        new: { isEnabled: after.isEnabled, config: after.config },
        ...(reason ? { reason } : {}),
      },
    });
  }

  private present(r: any) {
    const defaults = defaultConfigFor(r.code)!;
    return {
      code: r.code,
      title: ruleTitle(r.code, r.name),
      name: r.name,
      description: r.description,
      whyItMatters: NARRATIVES[r.code]?.why ?? null,
      isEnabled: r.isEnabled,
      priority: r.priority,
      config: { ...defaults, ...(r.config as any) },
      defaultConfig: defaults,
      isDefault: same({ ...defaults, ...(r.config as any) }, defaults),
      limits: limitsFor(r.code),
      updatedAt: r.updatedAt ?? null,
    };
  }
}
