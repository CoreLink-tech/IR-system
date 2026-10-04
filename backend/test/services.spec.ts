import 'reflect-metadata';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { IncidentsService } from '../src/incidents/incidents.service';
import { BlockingService } from '../src/blocking/blocking.service';
import { IpsService } from '../src/ips/ips.service';
import { StatisticsService } from '../src/statistics/statistics.service';

const audit = () => ({ log: jest.fn(async () => undefined) });

describe('IncidentsService', () => {
  function make(incident: any | null = { id: 'i1', status: 'OPEN', resolvedAt: null }, user: any | null = { id: 'u2', email: 'ops@pishon.ng' }) {
    const timeline: any[] = []; const updates: any[] = []; const seen: any = {};
    const prisma: any = {
      securityIncident: {
        findMany: async (a: any) => { seen.find = a; return ['row']; },
        count: async (a: any) => { seen.count = a; return 1; },
        findUnique: async (a: any) => { seen.unique = a; return incident; },
        update: async (a: any) => { updates.push(a); return { ...incident, ...a.data }; },
      },
      securityIncidentTimeline: { create: async ({ data }: any) => { timeline.push(data); } },
      securityUser: { findUnique: async () => user },
    };
    const a = audit();
    return { svc: new IncidentsService(prisma, a as any), timeline, updates, seen, audit: a };
  }
  const page = { page: 1, pageSize: 25, skip: 0, take: 25, sortBy: 'createdAt', sortOrder: 'desc' as const };

  it('lists with only the filters that were given, and the page and sort asked for', async () => {
    const m = make();
    const r = await m.svc.list({ ...page, skip: 50, filters: { status: 'OPEN', severity: 'HIGH' } });
    expect(r).toEqual({ data: ['row'], total: 1 });
    expect(m.seen.find).toMatchObject({ where: { status: 'OPEN', severity: 'HIGH' }, skip: 50, take: 25, orderBy: { createdAt: 'desc' } });
    expect(m.seen.find.where).not.toHaveProperty('sourceIp');
    expect(m.seen.count.where).toEqual(m.seen.find.where);
  });

  it('returns an incident with its timeline and a capped number of events', async () => {
    const m = make();
    await m.svc.findOne('i1');
    expect(m.seen.unique.include.timeline).toEqual({ orderBy: { createdAt: 'asc' } });
    expect(m.seen.unique.include.events.take).toBe(200);
  });

  it('answers 404 for a missing incident', async () => {
    await expect(make(null).svc.findOne('x')).rejects.toBeInstanceOf(NotFoundException);
    await expect(make(null).svc.updateStatus('x', 'RESOLVED', undefined, 'u1', 'a')).rejects.toBeInstanceOf(NotFoundException);
    await expect(make(null).svc.assign('x', 'u2', 'u1', 'a')).rejects.toBeInstanceOf(NotFoundException);
  });

  it('stamps the resolution time when resolving or closing as a false alarm, with notes', async () => {
    for (const status of ['RESOLVED', 'FALSE_POSITIVE']) {
      const m = make();
      await m.svc.updateStatus('i1', status, 'Reset passwords', 'u1', 'admin@pishon.ng');
      expect(m.updates[0].data).toMatchObject({ status, resolutionNotes: 'Reset passwords' });
      expect(m.updates[0].data.resolvedAt).toBeInstanceOf(Date);
    }
  });

  it('does not stamp a resolution time for in-progress statuses', async () => {
    const m = make();
    await m.svc.updateStatus('i1', 'INVESTIGATING', undefined, 'u1', 'admin');
    expect(m.updates[0].data).toEqual({ status: 'INVESTIGATING' });
  });

  it('clears the old resolution time when an incident is reopened', async () => {
    const m = make({ id: 'i1', status: 'RESOLVED', resolvedAt: new Date('2026-10-01T00:00:00Z') });
    await m.svc.updateStatus('i1', 'OPEN', 'Activity returned', 'u1', 'admin');
    expect(m.updates[0].data).toMatchObject({ status: 'OPEN', resolvedAt: null });
  });

  it('records who changed the status, in the timeline and the audit log', async () => {
    const m = make();
    await m.svc.updateStatus('i1', 'CONTAINED', 'Blocked at the firewall', 'u1', 'admin@pishon.ng');
    expect(m.timeline[0]).toEqual({ incidentId: 'i1', action: 'status.CONTAINED', actor: 'admin@pishon.ng', details: 'Blocked at the firewall' });
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'u1', action: 'incident.update', targetId: 'i1', metadata: { status: 'CONTAINED' },
    }));
  });

  it('assigns to an existing user and records it', async () => {
    const m = make();
    await m.svc.assign('i1', 'u2', 'u1', 'admin@pishon.ng');
    expect(m.updates[0].data).toEqual({ assignedTo: 'u2' });
    expect(m.timeline[0]).toMatchObject({ action: 'assigned', details: 'Assigned to ops@pishon.ng' });
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'incident.assign' }));
  });

  it('refuses to assign to a user that does not exist', async () => {
    const m = make({ id: 'i1' }, null);
    await expect(m.svc.assign('i1', 'ghost', 'u1', 'a')).rejects.toThrow('User not found');
    expect(m.updates).toHaveLength(0);
  });
});

describe('BlockingService', () => {
  function make(o: { allow?: any; existing?: any } = {}) {
    const created: any[] = []; const deactivated: any[] = []; const deleted: any[] = []; const upserts: any[] = [];
    let blockQuery: any;
    const prisma: any = {
      securityIpAllowlist: {
        findUnique: async () => o.allow ?? null,
        upsert: async (a: any) => { upserts.push(a); return a.create; },
        deleteMany: async (a: any) => { deleted.push(a); return { count: 1 }; },
        findMany: async () => ['allowed'],
      },
      securityIpBlock: {
        findFirst: async () => o.existing ?? null,
        findMany: async (a: any) => { blockQuery = a; return [
          { ipAddress: '198.51.100.7', reason: 'r', expiresAt: null, isPermanent: true, automatic: false, createdAt: new Date(), secret: 'internal' },
        ]; },
        updateMany: async (a: any) => { deactivated.push(a); return { count: 2 }; },
        create: async ({ data }: any) => { created.push(data); return data; },
      },
    };
    const a = audit();
    return { svc: new BlockingService(prisma, a as any), created, deactivated, deleted, upserts, audit: a, get query() { return blockQuery; } };
  }

  it('blocks for the default time when no length is given, and records the administrator', async () => {
    const m = make();
    await m.svc.block('198.51.100.7', { reason: 'abuse', administratorId: 'u1' });
    expect(m.created[0]).toMatchObject({ ipAddress: '198.51.100.7', action: 'BLOCK', isPermanent: false, active: true, automatic: false, administratorId: 'u1' });
    const minutes = (m.created[0].expiresAt.getTime() - Date.now()) / 60000;
    expect(minutes).toBeGreaterThan(59); expect(minutes).toBeLessThanOrEqual(60.1);
  });

  it('honours a custom length, and permanent blocks never expire', async () => {
    const a = make(); await a.svc.block('198.51.100.7', { reason: 'r', ttlMinutes: 10 });
    expect((a.created[0].expiresAt.getTime() - Date.now()) / 60000).toBeLessThanOrEqual(10.1);
    const b = make(); await b.svc.block('198.51.100.7', { reason: 'r', permanent: true });
    expect(b.created[0]).toMatchObject({ isPermanent: true, expiresAt: null });
  });

  it('replaces earlier active blocks for the same address instead of stacking them', async () => {
    const m = make();
    await m.svc.block('198.51.100.7', { reason: 'r' });
    expect(m.deactivated[0]).toEqual({ where: { ipAddress: '198.51.100.7', active: true }, data: { active: false } });
  });

  it('refuses invalid addresses, internal addresses and allowlisted addresses', async () => {
    const m = make();
    await expect(m.svc.block('999.1.1.1', { reason: 'r' })).rejects.toThrow('Invalid IP address');
    await expect(m.svc.block('127.1', { reason: 'r' })).rejects.toThrow('Invalid IP address');
    await expect(m.svc.block('10.0.0.5', { reason: 'r' })).rejects.toThrow('Internal and private addresses cannot be blocked');
    await expect(m.svc.block('127.0.0.1', { reason: 'r' })).rejects.toBeInstanceOf(BadRequestException);
    await expect(make({ allow: { expiresAt: null } }).svc.block('198.51.100.7', { reason: 'r' })).rejects.toThrow('allowlist');
    expect(m.created).toHaveLength(0);
  });

  it('treats an expired allowlist entry as not allowed', async () => {
    const m = make({ allow: { expiresAt: new Date(Date.now() - 1000) } });
    expect(await m.svc.isAllowed('198.51.100.7')).toBe(false);
    await expect(m.svc.block('198.51.100.7', { reason: 'r' })).resolves.toBeDefined();
  });

  it('audits manual blocks as the administrator and automatic ones as the system', async () => {
    const man = make(); await man.svc.block('198.51.100.7', { reason: 'r', administratorId: 'u1' });
    expect(man.audit.log).toHaveBeenCalledWith(expect.objectContaining({ actorType: 'USER', action: 'ip.block' }));
    const auto = make(); await auto.svc.block('198.51.100.7', { reason: 'r', automatic: true });
    expect(auto.audit.log).toHaveBeenCalledWith(expect.objectContaining({ actorType: 'SYSTEM', action: 'ip.autoblock' }));
  });

  it('automatic blocking skips internal and allowlisted addresses quietly', async () => {
    const internal = make(); expect(await internal.svc.autoBlock('10.1.1.1', { reason: 'r' })).toBeNull();
    const allowed = make({ allow: { expiresAt: null } }); expect(await allowed.svc.autoBlock('198.51.100.7', { reason: 'r' })).toBeNull();
    expect(internal.created).toHaveLength(0); expect(allowed.created).toHaveLength(0);
  });

  it('unblocks, keeps a record of the unblock, and says how many blocks it ended', async () => {
    const m = make();
    const r = await m.svc.unblock('198.51.100.7', 'False alarm', 'u1');
    expect(r).toEqual({ ok: true, deactivated: 2 });
    expect(m.created[0]).toMatchObject({ action: 'UNBLOCK', reason: 'False alarm', administratorId: 'u1', active: false });
    expect(m.audit.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'ip.unblock' }));
  });

  it('adds to the allowlist with an optional expiry, and removes entries', async () => {
    const m = make();
    await m.svc.allow('203.0.113.9', 'Office', 30, 'u1');
    expect(m.upserts[0].create).toMatchObject({ ipAddress: '203.0.113.9', reason: 'Office', addedBy: 'u1' });
    expect(m.upserts[0].create.expiresAt).toBeInstanceOf(Date);
    await m.svc.allow('203.0.113.9', 'Office', undefined, 'u1');
    expect(m.upserts[1].create.expiresAt).toBeNull();
    expect(await m.svc.unallow('203.0.113.9', 'u1')).toEqual({ ok: true });
    expect(m.deleted[0].where.ipAddress).toBe('203.0.113.9');
  });

  it('lists only blocks that are in force, and exposes only the fields the website needs', async () => {
    const m = make();
    const rows: any[] = await m.svc.activeBlocks();
    expect(m.query.where).toMatchObject({ action: 'BLOCK', active: true });
    expect(m.query.where.OR).toEqual([{ isPermanent: true }, { expiresAt: { gt: expect.any(Date) } }]);
    expect(Object.keys(rows[0]).sort()).toEqual(['automatic', 'createdAt', 'expiresAt', 'ipAddress', 'permanent', 'reason']);
  });

  it('caps history size and normalizes the address filter', async () => {
    const m = make();
    await m.svc.history('::ffff:198.51.100.7', 99999);
    expect(m.query.take).toBe(500);
    expect(m.query.where.ipAddress).toBe('198.51.100.7');
  });
});

describe('IpsService', () => {
  function make(row: any | null, intel: any = null) {
    const created: any[] = []; const updated: any[] = [];
    const prisma: any = {
      securityIp: {
        findUnique: async () => row,
        create: async ({ data }: any) => { created.push(data); return data; },
        update: async (a: any) => { updated.push(a); },
      },
      securityEvent: { findMany: async () => ['event'] },
      securityIpBlock: { findMany: async () => ['block'] },
    };
    const lookup = jest.fn(async () => { if (intel instanceof Error) throw intel; return intel; });
    return { svc: new IpsService(prisma, { lookup } as any), created, updated, lookup };
  }

  it('creates a record the first time an address is seen, counting a failed login', async () => {
    const m = make(null);
    await m.svc.touch('198.51.100.7', 'login_failed');
    expect(m.created[0]).toMatchObject({ ipAddress: '198.51.100.7', eventCount: 1, failedLogins: 1 });
    await m.svc.touch('198.51.100.7', 'page_view');
    expect(m.created[1].failedLogins).toBe(0);
  });

  it('updates counters on later events and leaves risk to the detection engine', async () => {
    const m = make({ ipAddress: '198.51.100.7', failedLogins: 40, isMalicious: true });
    await m.svc.touch('198.51.100.7', 'login_failed');
    expect(m.updated[0].data).toMatchObject({ eventCount: { increment: 1 }, failedLogins: { increment: 1 } });
    expect(m.updated[0].data).not.toHaveProperty('riskScore');
    expect(m.updated[0].data).not.toHaveProperty('riskLevel');
  });

  it('returns detail with recent events and blocks for a known address', async () => {
    const m = make({ ipAddress: '104.16.0.1' });
    const d: any = await m.svc.detail('104.16.0.1');
    expect(d).toMatchObject({ events: ['event'], blocks: ['block'], isPrivate: false });
  });

  it('looks up an unknown address, stores what it learned, and flags private addresses', async () => {
    const intel = { isVpn: false, isProxy: true, isTor: false, isDatacenter: false, isMalicious: false, reputationScore: 12, country: 'NG' };
    const m = make(null, intel);
    const d: any = await m.svc.detail('10.0.0.5');
    expect(m.created[0]).toMatchObject({ ipAddress: '10.0.0.5', isProxy: true, country: 'NG', reputationScore: 12 });
    expect(d.isPrivate).toBe(true);
    expect(d.events).toEqual([]);
  });

  it('answers 404 when an unknown address cannot be looked up', async () => {
    await expect(make(null, new Error('provider down')).svc.detail('198.51.100.7')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('StatisticsService', () => {
  it('assembles the dashboard summary from counts and groupings', async () => {
    const counts: Record<string, number> = { OPEN: 3, INVESTIGATING: 2, CONTAINED: 1, RESOLVED: 9, FALSE_POSITIVE: 4 };
    const prisma: any = {
      securityEvent: {
        count: async ({ where }: any) => {
          const since = Date.now() - where.occurredAt.gte.getTime();
          return since < 2 * 86400000 ? 10 : since < 8 * 86400000 ? 70 : 300;
        },
        groupBy: async ({ by }: any) => {
          if (by[0] === 'ipAddress') return [{ ipAddress: '198.51.100.7', _count: { ipAddress: 40 } }];
          if (by[0] === 'eventType') return [{ eventType: 'login_failed', _count: { eventType: 55 } }];
          return [{ riskLevel: 'NORMAL', _count: { riskLevel: 90 } }];
        },
      },
      securityIncident: {
        count: async ({ where }: any) => (where.severity === 'CRITICAL' ? 2 : counts[where.status]),
      },
      securityIpBlock: { count: async () => 5 },
      securityIpAllowlist: { count: async () => 7 },
    };
    const s: any = await new StatisticsService(prisma).summary();
    expect(s.events).toEqual({ last24h: 10, last7d: 70, last30d: 300 });
    expect(s.incidents).toEqual({ open: 3, investigating: 2, contained: 1, resolved: 9, falsePositive: 4, critical24h: 2 });
    expect(s.blocking).toEqual({ active: 5, allowlisted: 7 });
    expect(s.topIps).toEqual([{ ip: '198.51.100.7', count: 40 }]);
    expect(s.topEventTypes).toEqual([{ type: 'login_failed', count: 55 }]);
    expect(s.riskDistribution).toEqual([{ level: 'NORMAL', count: 90 }]);
    expect(new Date(s.generatedAt).getTime()).toBeLessThanOrEqual(Date.now());
  });
});
