import 'reflect-metadata';
import { ExecutionContext, INestApplication, UnauthorizedException, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { EventsController } from '../src/events/events.controller';
import { EventsService } from '../src/events/events.service';
import { SecuritySyncController } from '../src/security/security.controller';
import { BlockingService } from '../src/blocking/blocking.service';
import { IncidentsController } from '../src/incidents/incidents.controller';
import { IncidentsService } from '../src/incidents/incidents.service';
import { IpsController } from '../src/ips/ips.controller';
import { IpsService } from '../src/ips/ips.service';
import { IpIntelligenceService } from '../src/ips/ip-intelligence.service';
import { ApiKeysService } from '../src/api-keys/api-keys.service';
import { ApiKeyGuard } from '../src/common/guards/api-key.guard';
import { ScopesGuard } from '../src/common/guards/scopes.guard';
import { JwtAuthGuard } from '../src/common/guards/jwt-auth.guard';
import { JwtOrApiKeyGuard } from '../src/common/guards/jwt-or-api-key.guard';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { RequestIdInterceptor } from '../src/common/interceptors/request-id.interceptor';

process.env.API_KEY_PREFIX = 'PMS_';

/** Stands in for Passport: the role comes from x-role, no role means not signed in. */
class FakeJwt {
  canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const role = req.headers['x-role'];
    // The real guard (Passport) answers 401 when there is no valid login.
    if (!role) throw new UnauthorizedException();
    req.actor = { type: 'USER', id: 'u1', label: 'tester@pishon.ng', role };
    return true;
  }
}

const KEYS: Record<string, any> = {
  PMS_events: { id: 'k1', name: 'website', scopes: 'events:write' },
  PMS_block: { id: 'k2', name: 'blocklist', scopes: 'block:read' },
  PMS_both: { id: 'k3', name: 'all', scopes: 'events:write,block:read' },
};

describe('HTTP access chain (real guards, validation and error handling)', () => {
  let app: INestApplication;
  const events = {
    ingest: jest.fn(async (dto: any) => ({ id: 'e1', riskScore: 0, riskLevel: 'NORMAL', incidentId: null, echo: dto.event_type })),
    list: jest.fn(async () => ({ data: [], total: 0 })),
    findOne: jest.fn(async (id: string) => (id === 'missing' ? null : { id })),
  };
  const blocking = {
    activeBlocks: jest.fn(async () => [{ ipAddress: '198.51.100.7' }]),
    history: jest.fn(async () => [{ ipAddress: '198.51.100.7' }]),
  };
  const incidents = {
    list: jest.fn(async () => ({ data: [], total: 0 })),
    findOne: jest.fn(async () => ({ id: 'i1', title: 't', timeline: [{ action: 'x' }], events: [{ ipAddress: '198.51.100.7', userId: 'u9' }] })),
  };
  const ips = { detail: jest.fn(async () => ({ ip: { ipAddress: '198.51.100.7' }, events: [{ id: 'e' }], blocks: [] })) };
  const intel = { lookup: jest.fn(), providerNames: [] };
  const apiKeys = { verifyApiKey: jest.fn(async (raw: string) => KEYS[raw.slice(0, raw.indexOf('_', 4) > 0 ? raw.indexOf('_', 4) : undefined)] ?? KEYS[raw] ?? null) };

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      controllers: [EventsController, SecuritySyncController, IncidentsController, IpsController],
      providers: [
        { provide: EventsService, useValue: events },
        { provide: BlockingService, useValue: blocking },
        { provide: IncidentsService, useValue: incidents },
        { provide: IpsService, useValue: ips },
        { provide: IpIntelligenceService, useValue: intel },
        { provide: ApiKeysService, useValue: apiKeys },
        ApiKeyGuard, ScopesGuard, JwtOrApiKeyGuard,
        { provide: JwtAuthGuard, useClass: FakeJwt },
      ],
    }).overrideGuard(JwtAuthGuard).useClass(FakeJwt).compile();
    app = mod.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true, transformOptions: { enableImplicitConversion: true } }));
    app.useGlobalFilters(new AllExceptionsFilter());
    app.useGlobalInterceptors(new RequestIdInterceptor());
    await app.init();
  });
  afterAll(() => app.close());
  beforeEach(() => jest.clearAllMocks());

  const http = () => request(app.getHttpServer());
  const asKey = (r: request.Test, key: string) => r.set('Authorization', `Bearer ${key}`);
  const asRole = (r: request.Test, role: string) => r.set('Authorization', 'Bearer eyJ.jwt.token').set('x-role', role);
  const goodEvent = { event_type: 'login_failed', severity: 'MEDIUM', ip_address: '198.51.100.7' };

  describe('POST /api/v1/events', () => {
    it('accepts an event from a key with events:write', async () => {
      const res = await asKey(http().post('/api/v1/events').send(goodEvent), 'PMS_events').expect(201);
      expect(res.body).toMatchObject({ id: 'e1' });
      expect(res.headers['x-request-id']).toBeTruthy();
    });
    it('passes the key id and the sender address to the service', async () => {
      await asKey(http().post('/api/v1/events').send(goodEvent), 'PMS_events').expect(201);
      expect(events.ingest).toHaveBeenCalledWith(expect.objectContaining({ event_type: 'login_failed' }), expect.objectContaining({ apiKeyId: 'k1' }));
    });
    it('refuses a key without events:write', async () => {
      await asKey(http().post('/api/v1/events').send(goodEvent), 'PMS_block').expect(403);
      expect(events.ingest).not.toHaveBeenCalled();
    });
    it('refuses anonymous callers, wrong credentials and administrator logins', async () => {
      await http().post('/api/v1/events').send(goodEvent).expect(401);
      await asKey(http().post('/api/v1/events').send(goodEvent), 'PMS_unknown').expect(401);
      await asRole(http().post('/api/v1/events').send(goodEvent), 'SUPER_ADMIN').expect(401);
      expect(events.ingest).not.toHaveBeenCalled();
    });
    it('rejects an invalid event with a list of what is wrong', async () => {
      const res = await asKey(http().post('/api/v1/events').send({ severity: 'URGENT' }), 'PMS_events').expect(400);
      expect(res.body.message.join(' ')).toMatch(/event_type/);
      expect(res.body.message.join(' ')).toMatch(/severity/);
      expect(res.body.requestId).toBeTruthy();
    });
    it('rejects unknown fields rather than silently storing them', async () => {
      await asKey(http().post('/api/v1/events').send({ ...goodEvent, is_admin: true }), 'PMS_events').expect(400);
    });
    it('never reveals internal error detail', async () => {
      events.ingest.mockRejectedValueOnce(new Error('ECONNREFUSED 10.1.2.3:3306 using password'));
      const res = await asKey(http().post('/api/v1/events').send(goodEvent), 'PMS_events').expect(500);
      expect(res.body.message).toBe('Internal server error');
      expect(JSON.stringify(res.body)).not.toContain('10.1.2.3');
    });
  });

  describe('blocklist routes serve both the website key and administrators', () => {
    it('lets the website key read the blocklist', async () => {
      const res = await asKey(http().get('/api/v1/security/blocked-ips'), 'PMS_block').expect(200);
      expect(res.body).toEqual({ data: [{ ipAddress: '198.51.100.7' }] });
    });
    it('lets an administrator read the same route with a login (regression: this used to answer 401)', async () => {
      for (const role of ['SUPER_ADMIN', 'SECURITY_ADMIN', 'ANALYST', 'VIEWER']) {
        await asRole(http().get('/api/v1/security/blocked-ips'), role).expect(200);
      }
    });
    it('refuses a key that cannot read blocks, and anonymous callers', async () => {
      await asKey(http().get('/api/v1/security/blocked-ips'), 'PMS_events').expect(403);
      await http().get('/api/v1/security/blocked-ips').expect(401);
      expect(blocking.activeBlocks).not.toHaveBeenCalled();
    });
    it('keeps block history for analysts and above, and for the key', async () => {
      await asRole(http().get('/api/v1/security/blocks/history'), 'VIEWER').expect(403);
      await asRole(http().get('/api/v1/security/blocks/history?ip=198.51.100.7&limit=5'), 'ANALYST').expect(200);
      expect(blocking.history).toHaveBeenLastCalledWith('198.51.100.7', 5);
      await asKey(http().get('/api/v1/security/blocks/history'), 'PMS_block').expect(200);
      expect(blocking.history).toHaveBeenLastCalledWith(undefined, 100);
    });
    it('caps and sanitizes the history limit', async () => {
      await asKey(http().get('/api/v1/security/blocks/history?limit=99999'), 'PMS_block').expect(200);
      expect(blocking.history).toHaveBeenLastCalledWith(undefined, 500);
      await asKey(http().get('/api/v1/security/blocks/history?limit=-3'), 'PMS_block').expect(200);
      expect(blocking.history).toHaveBeenLastCalledWith(undefined, 100);
      await asKey(http().get('/api/v1/security/blocks/history?limit=abc'), 'PMS_block').expect(200);
      expect(blocking.history).toHaveBeenLastCalledWith(undefined, 100);
    });
  });

  describe('raw events', () => {
    it('are closed to viewers and open to analysts', async () => {
      await asRole(http().get('/api/v1/events'), 'VIEWER').expect(403);
      await asRole(http().get('/api/v1/events/e1'), 'VIEWER').expect(403);
      await asRole(http().get('/api/v1/events'), 'ANALYST').expect(200);
      await asRole(http().get('/api/v1/events/e1'), 'ANALYST').expect(200);
    });
    it('answer 404 for a missing event, and need a login', async () => {
      await asRole(http().get('/api/v1/events/missing'), 'ANALYST').expect(404);
      await http().get('/api/v1/events').expect(401);
    });
    it('ignore a sort column that is not allowed, and pass paging through', async () => {
      await asRole(http().get('/api/v1/events?sortBy=metadata&page=2&pageSize=10'), 'ANALYST').expect(200);
      expect(events.list).toHaveBeenCalledWith(expect.objectContaining({ sortBy: 'occurredAt', skip: 10, take: 10 }));
    });
  });

  describe('viewers get the story without the raw evidence', () => {
    it('incident detail drops the raw events for viewers but keeps the timeline', async () => {
      const res = await asRole(http().get('/api/v1/incidents/i1'), 'VIEWER').expect(200);
      expect(res.body.timeline).toHaveLength(1);
      expect(res.body).not.toHaveProperty('events');
      expect(JSON.stringify(res.body)).not.toContain('u9');
    });
    it('incident detail keeps the raw events for analysts', async () => {
      const res = await asRole(http().get('/api/v1/incidents/i1'), 'ANALYST').expect(200);
      expect(res.body.events).toHaveLength(1);
    });
    it('IP detail drops the event history for viewers', async () => {
      const v = await asRole(http().get('/api/v1/ips/198.51.100.7'), 'VIEWER').expect(200);
      expect(v.body.events).toEqual([]);
      expect(v.body.ip.ipAddress).toBe('198.51.100.7');
      const a = await asRole(http().get('/api/v1/ips/198.51.100.7'), 'ANALYST').expect(200);
      expect(a.body.events).toHaveLength(1);
    });
  });

  describe('input handling on lists', () => {
    it('falls back to a safe sort column for incidents', async () => {
      await asRole(http().get('/api/v1/incidents?sortBy=passwordHash'), 'ANALYST').expect(200);
      expect(incidents.list).toHaveBeenCalledWith(expect.objectContaining({ sortBy: 'createdAt' }));
    });
  });
});
