import 'reflect-metadata';
import { ExecutionContext, ForbiddenException, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { ApiKeysService } from '../src/api-keys/api-keys.service';
import { CreateApiKeyDto } from '../src/api-keys/dto';
import { ApiKeyGuard } from '../src/common/guards/api-key.guard';
import { ScopesGuard } from '../src/common/guards/scopes.guard';
import { JwtOrApiKeyGuard } from '../src/common/guards/jwt-or-api-key.guard';
import { Scopes } from '../src/common/decorators/scopes.decorator';
import { Roles } from '../src/common/decorators/roles.decorator';

process.env.API_KEY_PREFIX = 'PMS_';
process.env.API_KEY_HASH_PEPPER = 'test-pepper';

function keyStore() {
  const rows: any[] = [];
  let n = 0;
  const prisma: any = {
    securityApiKey: {
      create: async ({ data }: any) => { const r = { id: `k${++n}`, isActive: true, revokedAt: null, lastUsedAt: null, createdAt: new Date(), ...data }; rows.push(r); return r; },
      findFirst: async ({ where }: any) => rows.find((r) => r.keyPrefix === where.keyPrefix) ?? null,
      findUnique: async ({ where }: any) => rows.find((r) => r.id === where.id) ?? null,
      findMany: async ({ select }: any) => rows.map((r) => Object.fromEntries(Object.keys(select).map((k) => [k, r[k]]))),
      update: async ({ where, data }: any) => Object.assign(rows.find((r) => r.id === where.id), data),
    },
  };
  return { rows, svc: new ApiKeysService(prisma) };
}

describe('ApiKeysService', () => {
  it('returns the raw key once and stores only a hash', async () => {
    const { rows, svc } = keyStore();
    const created = await svc.create({ name: 'website', scopes: ['events:write', 'block:read'] });
    expect(created.apiKey.startsWith('PMS_')).toBe(true);
    expect(rows[0].keyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rows)).not.toContain(created.apiKey);
    expect(created.scopes).toEqual(['events:write', 'block:read']);
  });

  it('verifies a genuine key and records when it was last used', async () => {
    const { rows, svc } = keyStore();
    const { apiKey } = await svc.create({ name: 'website', scopes: ['events:write'] });
    expect(await svc.verifyApiKey(apiKey)).toMatchObject({ name: 'website' });
    expect(rows[0].lastUsedAt).toBeInstanceOf(Date);
  });

  it('rejects a key with the right prefix but the wrong secret', async () => {
    const { svc } = keyStore();
    const { apiKey } = await svc.create({ name: 'website', scopes: ['events:write'] });
    expect(await svc.verifyApiKey(apiKey.slice(0, -4) + 'AAAA')).toBeNull();
  });

  it('rejects an unknown key', async () => {
    expect(await keyStore().svc.verifyApiKey('PMS_0000000000000000notarealkey')).toBeNull();
  });

  it('rejects a revoked key', async () => {
    const { rows, svc } = keyStore();
    const { apiKey, id } = await svc.create({ name: 'website', scopes: ['events:write'] });
    await svc.revoke(id);
    expect(rows[0]).toMatchObject({ isActive: false, revokedAt: expect.any(Date) });
    expect(await svc.verifyApiKey(apiKey)).toBeNull();
  });

  it('rejects an expired key but accepts one that has not expired', async () => {
    const { rows, svc } = keyStore();
    const a = await svc.create({ name: 'a', scopes: ['events:write'], expiresInDays: 1 });
    const b = await svc.create({ name: 'b', scopes: ['events:write'], expiresInDays: 1 });
    rows[1].expiresAt = new Date(Date.now() - 1000);
    expect(await svc.verifyApiKey(a.apiKey)).not.toBeNull();
    expect(await svc.verifyApiKey(b.apiKey)).toBeNull();
  });

  it('treats zero or missing expiry as no expiry', async () => {
    const { rows, svc } = keyStore();
    await svc.create({ name: 'a', scopes: ['events:write'], expiresInDays: 0 });
    await svc.create({ name: 'b', scopes: ['events:write'] });
    expect(rows.map((r) => r.expiresAt)).toEqual([null, null]);
  });

  it('never lists key hashes', async () => {
    const { svc } = keyStore();
    await svc.create({ name: 'website', scopes: ['events:write'] });
    const list: any[] = await svc.list();
    expect(JSON.stringify(list)).not.toContain('keyHash');
    expect(list[0]).toHaveProperty('keyPrefix');
  });

  it('rotation issues a working replacement with the same scopes and revokes the old key', async () => {
    const { svc } = keyStore();
    const old = await svc.create({ name: 'website', scopes: ['events:write', 'block:read'] }, 'admin1');
    const next = await svc.rotate(old.id);
    expect(next.name).toBe('website (rotated)');
    expect(next.scopes).toEqual(['events:write', 'block:read']);
    expect(await svc.verifyApiKey(old.apiKey)).toBeNull();
    expect(await svc.verifyApiKey(next.apiKey)).not.toBeNull();
  });

  it('rotation keeps an expiry for a key that had one', async () => {
    const { svc } = keyStore();
    const old = await svc.create({ name: 'k', scopes: ['events:write'], expiresInDays: 30 });
    const next = await svc.rotate(old.id);
    expect(next.expiresAt).toBeInstanceOf(Date);
    const days = (next.expiresAt!.getTime() - Date.now()) / 86400000;
    expect(days).toBeGreaterThan(28);
    expect(days).toBeLessThanOrEqual(30.1);
  });

  it('revoking or rotating an unknown key is a 404', async () => {
    const { svc } = keyStore();
    await expect(svc.revoke('nope')).rejects.toBeInstanceOf(NotFoundException);
    await expect(svc.rotate('nope')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('CreateApiKeyDto', () => {
  const check = async (o: any) => (await validate(plainToInstance(CreateApiKeyDto, o))).map((e) => e.property);
  it('accepts known scopes', async () => {
    expect(await check({ name: 'k', scopes: ['events:write', 'block:read'] })).toEqual([]);
  });
  it('rejects invented scopes, wildcards and empty lists', async () => {
    expect(await check({ name: 'k', scopes: ['admin'] })).toContain('scopes');
    expect(await check({ name: 'k', scopes: ['*'] })).toContain('scopes');
    expect(await check({ name: 'k', scopes: ['events:write', 'events:wirte'] })).toContain('scopes');
    expect(await check({ name: 'k', scopes: [] })).toContain('scopes');
  });
  it('requires a name and a sensible expiry', async () => {
    expect(await check({ scopes: ['events:write'] })).toContain('name');
    expect(await check({ name: 'k', scopes: ['events:write'], expiresInDays: -1 })).toContain('expiresInDays');
  });
});

function context(headers: Record<string, string>, handler: Function = () => undefined, extra: any = {}) {
  const req: any = { headers, socket: { remoteAddress: '203.0.113.7' }, ...extra };
  const ctx = {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => handler,
    getClass: () => class {},
  } as unknown as ExecutionContext;
  return { req, ctx };
}

describe('ApiKeyGuard', () => {
  const guardWith = (verify: (raw: string) => any) => new ApiKeyGuard({ verifyApiKey: async (r: string) => verify(r) } as any);
  const key = { id: 'k1', name: 'website', scopes: 'events:write, block:read' };

  it('rejects a missing or malformed Authorization header', async () => {
    const g = guardWith(() => key);
    await expect(g.canActivate(context({}).ctx)).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(g.canActivate(context({ authorization: 'Basic abc' }).ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects a token without the key prefix before touching the database', async () => {
    const verify = jest.fn();
    await expect(guardWith(verify).canActivate(context({ authorization: 'Bearer eyJhbGciOi.jwt.token' }).ctx)).rejects.toThrow('Invalid API key prefix');
    expect(verify).not.toHaveBeenCalled();
  });

  it('rejects a key the service does not recognise', async () => {
    await expect(guardWith(() => null).canActivate(context({ authorization: 'Bearer PMS_abc' }).ctx)).rejects.toThrow('Invalid or expired API key');
  });

  it('accepts a valid key and records who is acting, with trimmed scopes', async () => {
    const { req, ctx } = context({ authorization: 'Bearer PMS_good', 'user-agent': 'php-client' });
    expect(await guardWith(() => key).canActivate(ctx)).toBe(true);
    expect(req.actor).toMatchObject({ type: 'API_KEY', id: 'k1', label: 'website', scopes: ['events:write', 'block:read'], userAgent: 'php-client' });
    expect(req.apiKey).toBe(key);
  });
});

describe('ScopesGuard', () => {
  class Holder { @Scopes('events:write') write() {} @Scopes('events:write', 'block:read') both() {} open() {} }
  const run = (handler: Function, actor: any) => {
    const { ctx } = context({}, handler, { actor });
    return () => new ScopesGuard(new Reflector()).canActivate(ctx);
  };

  it('allows a key that holds the scope', () => {
    expect(run(Holder.prototype.write, { type: 'API_KEY', scopes: ['events:write'] })()).toBe(true);
  });
  it('refuses a key that lacks the scope', () => {
    expect(run(Holder.prototype.write, { type: 'API_KEY', scopes: ['block:read'] })).toThrow(ForbiddenException);
  });
  it('requires every listed scope, not just one', () => {
    expect(run(Holder.prototype.both, { type: 'API_KEY', scopes: ['events:write'] })).toThrow(ForbiddenException);
    expect(run(Holder.prototype.both, { type: 'API_KEY', scopes: ['events:write', 'block:read'] })()).toBe(true);
  });
  it('refuses when nobody is identified', () => {
    expect(run(Holder.prototype.write, undefined)).toThrow('No actor');
  });
  it('lets signed-in administrators through; their access is governed by roles', () => {
    expect(run(Holder.prototype.write, { type: 'USER', role: 'VIEWER' })()).toBe(true);
  });
  it('does nothing for routes that name no scope', () => {
    expect(run(Holder.prototype.open, undefined)()).toBe(true);
  });
});

describe('JwtOrApiKeyGuard', () => {
  class Routes {
    @Scopes('block:read') @Roles('SUPER_ADMIN', 'ANALYST') read() {}
  }
  const key = { id: 'k1', name: 'website', scopes: 'block:read' };

  function build(opts: { verify?: (raw: string) => any; jwt?: (ctx: any) => any }) {
    const apiKeyGuard = new ApiKeyGuard({ verifyApiKey: async (r: string) => (opts.verify ? opts.verify(r) : key) } as any);
    const jwtGuard: any = { canActivate: jest.fn(async (c: any) => (opts.jwt ? opts.jwt(c) : true)) };
    return { guard: new JwtOrApiKeyGuard(new Reflector(), apiKeyGuard, jwtGuard), jwtGuard };
  }

  it('sends a PMS_ token down the API key path and never calls the JWT guard', async () => {
    const { guard, jwtGuard } = build({});
    const { ctx, req } = context({ authorization: 'Bearer PMS_abc' }, Routes.prototype.read);
    expect(await guard.canActivate(ctx)).toBe(true);
    expect(req.actor.type).toBe('API_KEY');
    expect(jwtGuard.canActivate).not.toHaveBeenCalled();
  });

  it('refuses an API key that lacks the required scope', async () => {
    const { guard } = build({ verify: () => ({ ...key, scopes: 'events:write' }) });
    await expect(guard.canActivate(context({ authorization: 'Bearer PMS_abc' }, Routes.prototype.read).ctx)).rejects.toThrow('Missing required scope');
  });

  it('refuses an unknown API key', async () => {
    const { guard } = build({ verify: () => null });
    await expect(guard.canActivate(context({ authorization: 'Bearer PMS_abc' }, Routes.prototype.read).ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('sends any other token down the JWT path and enforces roles', async () => {
    const { guard, jwtGuard } = build({});
    const ok = context({ authorization: 'Bearer eyJ.jwt.x' }, Routes.prototype.read, { actor: { role: 'ANALYST' } });
    expect(await guard.canActivate(ok.ctx)).toBe(true);
    expect(jwtGuard.canActivate).toHaveBeenCalled();
    const wrong = context({ authorization: 'Bearer eyJ.jwt.x' }, Routes.prototype.read, { actor: { role: 'VIEWER' } });
    await expect(guard.canActivate(wrong.ctx)).rejects.toThrow('Insufficient role');
  });

  it('refuses when the JWT guard says no, or when a JWT user has no role', async () => {
    const denied = build({ jwt: () => false });
    expect(await denied.guard.canActivate(context({ authorization: 'Bearer eyJ.x.y' }, Routes.prototype.read).ctx)).toBe(false);
    const norole = build({});
    await expect(norole.guard.canActivate(context({ authorization: 'Bearer eyJ.x.y' }, Routes.prototype.read, { actor: {} }).ctx)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses a request with no credentials at all', async () => {
    const { guard } = build({ jwt: () => { throw new UnauthorizedException(); } });
    await expect(guard.canActivate(context({}, Routes.prototype.read).ctx)).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
