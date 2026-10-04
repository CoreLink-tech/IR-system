import { describeRoutes, RouteInfo } from './helpers/routes';

/**
 * Reads every route from the controllers' decorators and checks the access policy.
 * If someone adds a route and forgets to protect it, or widens access to a sensitive
 * route, this suite fails.
 */
const routes = describeRoutes();
const byKey = new Map(routes.map((r) => [r.key, r]));
const AUTH_GUARDS = ['JwtAuthGuard', 'ApiKeyGuard', 'JwtOrApiKeyGuard'];
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const ALL = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER'];
const ANALYST_UP = ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST'];
const ADMIN = ['SUPER_ADMIN', 'SECURITY_ADMIN'];

describe('route inventory', () => {
  it('finds every route (guards against the inventory silently shrinking)', () => {
    expect(routes.length).toBe(31);
  });

  it('has no duplicated method and path, because the first registration would shadow the second', () => {
    const keys = routes.map((r) => r.key);
    expect(keys.filter((k, i) => keys.indexOf(k) !== i)).toEqual([]);
  });

  it('protects every route except the three public authentication routes', () => {
    const unprotected = routes.filter((r) => !r.guards.some((g) => AUDIT_GUARD_NAMES.includes(g)));
    expect(unprotected.map((r) => r.key).sort()).toEqual([
      'POST /api/v1/auth/login', 'POST /api/v1/auth/logout', 'POST /api/v1/auth/refresh',
    ]);
    expect(routes.filter((r) => r.isPublic).map((r) => r.key).sort()).toEqual(
      unprotected.map((r) => r.key).sort());
  });
});
const AUDIT_GUARD_NAMES = AUTH_GUARDS;

describe('role rules', () => {
  const jwtRoutes = routes.filter((r) => r.guards.includes('JwtAuthGuard'));

  it('every administrator route names its allowed roles, except self-service password change', () => {
    const missing = jwtRoutes.filter((r) => r.roles.length === 0).map((r) => r.key);
    expect(missing).toEqual(['POST /api/v1/auth/change-password']);
    for (const r of jwtRoutes.filter((x) => x.roles.length > 0)) expect(r.guards).toContain('RolesGuard');
  });

  it('viewers can never change anything', () => {
    const bad = routes.filter((r) => MUTATING.has(r.method) && r.roles.includes('VIEWER')).map((r) => r.key);
    expect(bad).toEqual([]);
  });

  it('only the super admin can create users', () => {
    expect(byKey.get('POST /api/v1/auth/users')!.roles).toEqual(['SUPER_ADMIN']);
  });

  it('raw security data and credentials are closed to viewers', () => {
    const closed = [
      'GET /api/v1/events', 'GET /api/v1/events/:id', 'GET /api/v1/audit-logs', 'GET /api/v1/api-keys',
      'GET /api/v1/security/blocks/history', 'GET /api/v1/reports/technical/:id', 'GET /api/v1/reports/security-summary',
    ];
    for (const k of closed) expect(byKey.get(k)!.roles).not.toContain('VIEWER');
  });

  it('API keys and their rotation are for administrators only', () => {
    for (const k of ['GET /api/v1/api-keys', 'POST /api/v1/api-keys', 'DELETE /api/v1/api-keys/:id', 'POST /api/v1/api-keys/:id/rotate']) {
      expect(byKey.get(k)!.roles).toEqual(ADMIN);
    }
  });

  it('blocking, unblocking and the allowlist are for administrators only', () => {
    for (const k of ['POST /api/v1/security/block', 'POST /api/v1/security/unblock', 'POST /api/v1/security/allow', 'DELETE /api/v1/security/allow/:ip']) {
      expect(byKey.get(k)!.roles).toEqual(ADMIN);
    }
  });

  it('only administrators assign incidents; analysts may change their status', () => {
    expect(byKey.get('POST /api/v1/incidents/:id/assign')!.roles).toEqual(ADMIN);
    expect(byKey.get('POST /api/v1/incidents/:id/status')!.roles).toEqual(ANALYST_UP);
  });

  it('documents the full read matrix', () => {
    const expected: Record<string, string[]> = {
      'GET /api/v1/incidents': ALL, 'GET /api/v1/incidents/:id': ALL, 'GET /api/v1/ips/:ip': ALL,
      'GET /api/v1/statistics': ALL, 'GET /api/v1/security/allowlist': ALL,
      'GET /api/v1/reports/executive-summary': ALL, 'GET /api/v1/reports/incidents/:id': ALL,
      'GET /api/v1/events': ANALYST_UP, 'GET /api/v1/audit-logs': ANALYST_UP,
      'GET /api/v1/reports/technical/:id': ANALYST_UP, 'GET /api/v1/reports/security-summary': ANALYST_UP,
      'POST /api/v1/ips/:ip/refresh-intelligence': ANALYST_UP,
    };
    for (const [k, roles] of Object.entries(expected)) expect([k, byKey.get(k)!.roles]).toEqual([k, roles]);
  });
});

describe('API key rules', () => {
  const keyRoutes = routes.filter((r) => r.guards.includes('ApiKeyGuard') || r.guards.includes('JwtOrApiKeyGuard'));

  it('every route a key can call requires a named scope', () => {
    expect(keyRoutes.length).toBe(3);
    for (const r of keyRoutes) expect(r.scopes.length).toBeGreaterThan(0);
  });

  it('a key-only route also runs the scope check', () => {
    for (const r of keyRoutes.filter((x) => x.guards.includes('ApiKeyGuard'))) expect(r.guards).toContain('ScopesGuard');
  });

  it('the website key can write events and read the blocklist, and nothing else', () => {
    expect(byKey.get('POST /api/v1/events')!.scopes).toEqual(['events:write']);
    expect(byKey.get('GET /api/v1/security/blocked-ips')!.scopes).toEqual(['block:read']);
    expect(byKey.get('GET /api/v1/security/blocks/history')!.scopes).toEqual(['block:read']);
    expect(keyRoutes.map((r) => r.key).sort()).toEqual([
      'GET /api/v1/security/blocked-ips', 'GET /api/v1/security/blocks/history', 'POST /api/v1/events',
    ]);
  });

  it('the blocklist routes also accept administrators with the right roles', () => {
    expect(byKey.get('GET /api/v1/security/blocked-ips')!.roles).toEqual(ALL);
    expect(byKey.get('GET /api/v1/security/blocks/history')!.roles).toEqual(ANALYST_UP);
  });
});

export type { RouteInfo };
