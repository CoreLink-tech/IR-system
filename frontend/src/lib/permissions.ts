import matrix from './route-matrix.json';
import type { Role, User } from '@/api/types';

/**
 * What the interface may offer. The role lists come from route-matrix.json, which is
 * generated from the API's own route decorators (npm run export:routes in backend/), so the
 * dashboard cannot offer something the API would refuse. Components ask `can(user, 'x')`
 * and never compare role names themselves.
 */
const ROUTES = matrix as Record<string, Role[]>;

export const CAPABILITIES = {
  'incidents.read': 'GET /api/v1/incidents',
  'incidents.status': 'POST /api/v1/incidents/:id/status',
  'incidents.assign': 'POST /api/v1/incidents/:id/assign',
  'incidents.note': 'POST /api/v1/incidents/:id/notes',
  'events.read': 'GET /api/v1/events',
  'reports.executive': 'GET /api/v1/reports/executive-summary',
  'reports.incident': 'GET /api/v1/reports/incidents/:id',
  'reports.security': 'GET /api/v1/reports/security-summary',
  'reports.technical': 'GET /api/v1/reports/technical/:id',
  'ips.list': 'GET /api/v1/ips',
  'ips.read': 'GET /api/v1/ips/:ip',
  'ips.refresh': 'POST /api/v1/ips/:ip/refresh-intelligence',
  'blocks.read': 'GET /api/v1/security/blocked-ips',
  'blocks.history': 'GET /api/v1/security/blocks/history',
  'blocks.block': 'POST /api/v1/security/block',
  'blocks.unblock': 'POST /api/v1/security/unblock',
  'allowlist.read': 'GET /api/v1/security/allowlist',
  'allowlist.add': 'POST /api/v1/security/allow',
  'allowlist.remove': 'DELETE /api/v1/security/allow/:ip',
  'apikeys.manage': 'GET /api/v1/api-keys',
  'users.manage': 'GET /api/v1/auth/users',
  'users.assignable': 'GET /api/v1/auth/assignees',
  'rules.manage': 'GET /api/v1/rules',
  'audit.read': 'GET /api/v1/audit-logs',
  'settings.read': 'GET /api/v1/settings/operational',
} as const;

export type Capability = keyof typeof CAPABILITIES;

export function rolesFor(cap: Capability): Role[] {
  const roles = ROUTES[CAPABILITIES[cap]];
  if (!roles) throw new Error(`No API route behind capability "${cap}". Re-run npm run export:routes.`);
  return roles;
}

export function can(user: Pick<User, 'role'> | null | undefined, cap: Capability): boolean {
  return !!user && rolesFor(cap).includes(user.role);
}

export const ROLE_LABEL: Record<Role, string> = {
  SUPER_ADMIN: 'Super admin', SECURITY_ADMIN: 'Security admin', ANALYST: 'Analyst', VIEWER: 'Viewer',
};
