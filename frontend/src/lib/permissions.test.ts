import { describe, expect, it } from 'vitest';
import { CAPABILITIES, can, rolesFor, type Capability } from './permissions';
import matrix from './route-matrix.json';
import { ROLE_LIST, type Role } from '@/api/types';

const caps = Object.keys(CAPABILITIES) as Capability[];
const asUser = (role: Role) => ({ role });

describe('permissions come from the API route matrix', () => {
  it('every capability points at a real API route', () => {
    for (const c of caps) expect([c, CAPABILITIES[c] in matrix]).toEqual([c, true]);
  });
  it('can() agrees with the matrix for every capability and every role', () => {
    for (const c of caps) for (const r of ROLE_LIST) expect([c, r, can(asUser(r), c)]).toEqual([c, r, (matrix as Record<string, string[]>)[CAPABILITIES[c]].includes(r)]);
  });
  it('nobody is allowed when nobody is signed in', () => {
    for (const c of caps) { expect(can(null, c)).toBe(false); expect(can(undefined, c)).toBe(false); }
  });
  it('a viewer can read but never change anything or see raw activity', () => {
    const viewerMay = caps.filter((c) => can(asUser('VIEWER'), c)).sort();
    expect(viewerMay).toEqual(['allowlist.read', 'blocks.read', 'incidents.read', 'ips.read', 'reports.executive', 'reports.incident'].sort());
  });
  it('analysts investigate but cannot block, assign, or manage keys, users or rules', () => {
    for (const c of ['blocks.block', 'blocks.unblock', 'allowlist.add', 'allowlist.remove', 'incidents.assign', 'apikeys.manage', 'users.manage', 'rules.manage', 'settings.read'] as Capability[]) expect([c, can(asUser('ANALYST'), c)]).toEqual([c, false]);
    for (const c of ['events.read', 'reports.technical', 'reports.security', 'audit.read', 'blocks.history', 'ips.list', 'ips.refresh', 'incidents.status', 'incidents.note'] as Capability[]) expect([c, can(asUser('ANALYST'), c)]).toEqual([c, true]);
  });
  it('security admins manage blocks, keys, rules and assignments but not users', () => {
    for (const c of ['blocks.block', 'blocks.unblock', 'allowlist.add', 'allowlist.remove', 'incidents.assign', 'apikeys.manage', 'rules.manage', 'settings.read', 'users.assignable'] as Capability[]) expect([c, can(asUser('SECURITY_ADMIN'), c)]).toEqual([c, true]);
    expect(can(asUser('SECURITY_ADMIN'), 'users.manage')).toBe(false);
  });
  it('only the super admin manages users', () => {
    expect(rolesFor('users.manage')).toEqual(['SUPER_ADMIN']);
  });
  it('throws a helpful error if a capability has no route behind it', () => {
    expect(() => rolesFor('nope' as Capability)).toThrow(/export:routes/);
  });
});
