import 'reflect-metadata';
import { RequestMethod } from '@nestjs/common';
import { ROLES_KEY, SCOPES_KEY } from '../../src/common/constants';
import { IS_PUBLIC_KEY } from '../../src/common/decorators/public.decorator';
import { AuthController } from '../../src/auth/auth.controller';
import { ApiKeysController } from '../../src/api-keys/api-keys.controller';
import { AuditController } from '../../src/audit/audit.controller';
import { BlockingController } from '../../src/blocking/blocking.controller';
import { EventsController } from '../../src/events/events.controller';
import { IncidentsController } from '../../src/incidents/incidents.controller';
import { IpsController } from '../../src/ips/ips.controller';
import { ReportsController } from '../../src/reports/reports.controller';
import { StatisticsController } from '../../src/statistics/statistics.controller';
import { SecuritySyncController } from '../../src/security/security.controller';
import { RulesController } from '../../src/rules/rules.controller';
import { HealthController } from '../../src/health/health.controller';
import { SettingsController } from '../../src/settings/settings.controller';

export const CONTROLLERS: any[] = [
  AuthController, ApiKeysController, AuditController, BlockingController, EventsController,
  IncidentsController, IpsController, ReportsController, StatisticsController, SecuritySyncController,
  RulesController, HealthController, SettingsController,
];

export interface RouteInfo {
  key: string; // "GET /api/v1/events/:id"
  method: string;
  path: string;
  guards: string[];
  roles: string[];
  scopes: string[];
  isPublic: boolean;
}

const METHOD_NAMES: Record<number, string> = {
  [RequestMethod.GET]: 'GET', [RequestMethod.POST]: 'POST', [RequestMethod.PUT]: 'PUT',
  [RequestMethod.DELETE]: 'DELETE', [RequestMethod.PATCH]: 'PATCH',
};

const join = (a: string, b: string) => `/${[a, b].filter(Boolean).join('/')}`.replace(/\/+/g, '/');

/** Reads every route straight from the decorators on the controllers. */
export function describeRoutes(): RouteInfo[] {
  const out: RouteInfo[] = [];
  for (const C of CONTROLLERS) {
    const base: string = Reflect.getMetadata('path', C) ?? '';
    const classGuards: any[] = Reflect.getMetadata('__guards__', C) ?? [];
    for (const name of Object.getOwnPropertyNames(C.prototype)) {
      const fn = C.prototype[name];
      if (typeof fn !== 'function' || name === 'constructor') continue;
      const routePath = Reflect.getMetadata('path', fn);
      const method = Reflect.getMetadata('method', fn);
      if (routePath === undefined || method === undefined) continue;
      const guards = [...classGuards, ...(Reflect.getMetadata('__guards__', fn) ?? [])].map((g) => g.name);
      const get = (key: string) => Reflect.getMetadata(key, fn) ?? Reflect.getMetadata(key, C) ?? [];
      const path = join(base, routePath === '/' ? '' : routePath);
      out.push({
        key: `${METHOD_NAMES[method]} ${path}`,
        method: METHOD_NAMES[method], path, guards,
        roles: get(ROLES_KEY), scopes: get(SCOPES_KEY),
        isPublic: !!(Reflect.getMetadata(IS_PUBLIC_KEY, fn) ?? Reflect.getMetadata(IS_PUBLIC_KEY, C)),
      });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}
