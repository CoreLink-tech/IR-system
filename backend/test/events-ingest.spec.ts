import 'reflect-metadata';
import { BadRequestException } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { EventsService, isSensitiveKey, redactPath, sanitizeMetadata } from '../src/events/events.service';
import { CreateEventDto } from '../src/events/dto';

describe('isSensitiveKey', () => {
  it.each([
    'password', 'user_password', 'Password', 'passwd', 'pwd', 'secret', 'client_secret',
    'token', 'reset_token', 'resetToken', 'access_token', 'refresh_token', 'csrfToken',
    'api_key', 'apiKey', 'API-KEY', 'authorization', 'Authorization', 'cookie', 'set-cookie',
    'credit_card', 'card_number', 'cardNumber', 'cvv', 'CVV', 'card_pin', 'cardPin', 'pin', 'otp', 'ssn', 'private_key',
  ])('redacts %s', (k) => expect(isSensitiveKey(k)).toBe(true));

  it.each([
    'shipping_address', 'shippingMethod', 'mapping', 'typing', 'spinner', 'happiness', 'pinterest_board',
    'keyboard', 'monkey', 'turkey', 'author', 'authority', 'ip_address', 'user_id', 'email', 'order_id', 'amount', 'currency',
  ])('keeps %s', (k) => expect(isSensitiveKey(k)).toBe(false));
});

describe('sanitizeMetadata', () => {
  it('redacts sensitive fields at any depth, including inside arrays', () => {
    const out = sanitizeMetadata({
      email: 'a@b.ng', password: 'hunter2', nested: { reset_token: 'abc', ok: 1, deeper: [{ cardPin: '1234', note: 'x' }] },
    });
    expect(out).toEqual({
      email: 'a@b.ng', password: '[REDACTED]',
      nested: { reset_token: '[REDACTED]', ok: 1, deeper: [{ cardPin: '[REDACTED]', note: 'x' }] },
    });
  });

  it('keeps ordinary data that merely resembles a sensitive word', () => {
    expect(sanitizeMetadata({ shipping_address: '12 Marina Rd', mapping: 'a' })).toEqual({ shipping_address: '12 Marina Rd', mapping: 'a' });
  });

  it('redacts a sensitive key whatever its value type', () => {
    expect(sanitizeMetadata({ token: { a: 1 }, secret: 5, pin: true })).toEqual({ token: '[REDACTED]', secret: '[REDACTED]', pin: '[REDACTED]' });
  });

  it('limits string length, array size and depth', () => {
    const out: any = sanitizeMetadata({ big: 'x'.repeat(5000), list: Array.from({ length: 500 }, (_, i) => i) });
    expect(out.big.length).toBe(4099);
    expect(out.big.endsWith('...')).toBe(true);
    expect(out.list).toHaveLength(200);
    let deep: any = { v: 'bottom' };
    for (let i = 0; i < 10; i++) deep = { n: deep };
    expect(JSON.stringify(sanitizeMetadata(deep))).toContain('[truncated]');
  });

  it('passes null, numbers and booleans through, and stringifies anything else', () => {
    expect(sanitizeMetadata(null)).toBeNull();
    expect(sanitizeMetadata({ a: 1, b: true, c: null })).toEqual({ a: 1, b: true, c: null });
    expect(sanitizeMetadata(10n as any)).toBe('10');
  });
});

describe('redactPath', () => {
  it('removes the value of sensitive query parameters and keeps the rest', () => {
    expect(redactPath('/reset?token=abc123&lang=en')).toBe('/reset?token=[REDACTED]&lang=en');
    expect(redactPath('/login?next=/account&password=hunter2')).toBe('/login?next=/account&password=[REDACTED]');
    expect(redactPath('/api?API_KEY=zzz&page=2')).toBe('/api?API_KEY=[REDACTED]&page=2');
  });

  it('recognises encoded parameter names', () => {
    expect(redactPath('/x?reset%5Ftoken=abc')).toBe('/x?reset%5Ftoken=[REDACTED]');
  });

  it('leaves injection attempts visible so detection still works', () => {
    expect(redactPath('/search?q=<script>alert(1)</script>')).toBe('/search?q=<script>alert(1)</script>');
    expect(redactPath('/a?file=../../etc/passwd&token=t')).toBe('/a?file=../../etc/passwd&token=[REDACTED]');
  });

  it('leaves paths without a query, empty values and undefined alone', () => {
    expect(redactPath('/products/shoes')).toBe('/products/shoes');
    expect(redactPath(undefined)).toBeUndefined();
    expect(redactPath('')).toBe('');
  });

  it('keeps a fragment out of the redaction', () => {
    expect(redactPath('/p?token=abc#top')).toBe('/p?token=[REDACTED]#top');
  });
});

/** Builds an EventsService with call-order tracking. */
function pipeline(over: { touch?: () => any; detect?: () => any; raceOnCreate?: boolean } = {}) {
  const calls: string[] = [];
  const created: any[] = [];
  const prisma: any = {
    securityEvent: {
      findFirst: async ({ where }: any) => created.find((r) => r.apiKeyId === where.apiKeyId && r.externalId === where.externalId) ?? null,
      create: async ({ data }: any) => {
        if (data.externalId && over.raceOnCreate) {
          // Another copy of the same event was stored a moment ago, after our check.
          over.raceOnCreate = false;
          created.push({ id: 'winner', riskScore: 55, riskLevel: 'SUSPICIOUS', incidentId: 'incW', ...data });
          throw Object.assign(new Error('Unique constraint failed on apiKeyId, externalId'), { code: 'P2002' });
        }
        calls.push('store'); const row = { id: `e${created.length + 1}`, riskScore: 40, riskLevel: 'SUSPICIOUS', incidentId: 'inc1', ...data }; created.push(row); return row;
      },
    },
  };
  const audit = { log: jest.fn(async () => { calls.push('audit'); }) };
  const detection = { processEvent: jest.fn(async (e: any) => { calls.push('detect'); return over.detect ? over.detect() : { riskScore: 40, riskLevel: 'SUSPICIOUS', incidentId: 'inc1' }; }) };
  const ips = { touch: jest.fn(async () => { calls.push('touch'); if (over.touch) return over.touch(); }) };
  return { calls, created, audit, detection, ips, svc: new EventsService(prisma, audit as any, detection as any, ips as any) };
}

const base = { event_type: 'login_failed', severity: 'MEDIUM', ip_address: '198.51.100.7', user_id: 'u1' };
const ctx = { apiKeyId: 'k1', requestId: 'r1', ip: '10.0.0.9', userAgent: 'php' };

describe('EventsService.ingest', () => {
  it('stores, tracks the address, runs detection and audits, in that order', async () => {
    const p = pipeline();
    const r = await p.svc.ingest(base as any, ctx);
    expect(p.calls).toEqual(['store', 'touch', 'detect', 'audit']);
    expect(r).toEqual({ id: 'e1', riskScore: 40, riskLevel: 'SUSPICIOUS', incidentId: 'inc1' });
  });

  it('records which key sent the event and audits it as that key', async () => {
    const p = pipeline();
    await p.svc.ingest(base as any, ctx);
    expect(p.created[0].apiKeyId).toBe('k1');
    expect(p.audit.log).toHaveBeenCalledWith(expect.objectContaining({
      actorType: 'API_KEY', actorId: 'k1', action: 'event.ingest', targetId: 'e1', result: 'SUCCESS',
    }));
  });

  it('normalizes the reported address, including IPv4-mapped and long IPv6 forms', async () => {
    const a = pipeline(); await a.svc.ingest({ ...base, ip_address: '::ffff:198.51.100.7' } as any, ctx);
    expect(a.created[0].ipAddress).toBe('198.51.100.7');
    const b = pipeline(); await b.svc.ingest({ ...base, ip_address: '2001:0db8:0000:0000:0000:0000:0000:0001' } as any, ctx);
    expect(b.created[0].ipAddress).toBe('2001:db8::1');
  });

  it('uses the address the website reported, not the address of the website itself', async () => {
    const p = pipeline();
    await p.svc.ingest(base as any, ctx);
    expect(p.created[0].ipAddress).toBe('198.51.100.7');
  });

  it('falls back to the connecting address only when none is reported', async () => {
    const p = pipeline();
    await p.svc.ingest({ event_type: 'page_view', severity: 'INFO' } as any, { ...ctx, ip: '203.0.113.50' });
    expect(p.created[0].ipAddress).toBe('203.0.113.50');
  });

  it('keeps an event whose reported address is invalid, without an address, rather than dropping it', async () => {
    const p = pipeline();
    const r = await p.svc.ingest({ ...base, ip_address: 'not-an-ip' } as any, ctx);
    expect(p.created[0].ipAddress).toBeUndefined();
    expect(p.ips.touch).not.toHaveBeenCalled();
    expect(r.id).toBe('e1');
  });

  it('redacts secrets in metadata and in the request path before storing', async () => {
    const p = pipeline();
    await p.svc.ingest({ ...base, request_path: '/reset?token=abc&lang=en', metadata: { password: 'x', plan: 'pro' } } as any, ctx);
    expect(p.created[0].requestPath).toBe('/reset?token=[REDACTED]&lang=en');
    expect(p.created[0].metadata).toEqual({ password: '[REDACTED]', plan: 'pro' });
    expect(JSON.stringify(p.created[0])).not.toContain('abc');
  });

  it('defaults metadata to an empty object', async () => {
    const p = pipeline();
    await p.svc.ingest(base as any, ctx);
    expect(p.created[0].metadata).toEqual({});
  });

  it('uses the supplied timestamp, and now when none is given', async () => {
    const p = pipeline();
    await p.svc.ingest({ ...base, timestamp: '2026-10-02T10:00:00Z' } as any, ctx);
    expect(p.created[0].occurredAt.toISOString()).toBe('2026-10-02T10:00:00.000Z');
    await p.svc.ingest(base as any, ctx);
    expect(Math.abs(p.created[1].occurredAt.getTime() - Date.now())).toBeLessThan(2000);
  });

  it('rejects an unparseable timestamp and stores nothing', async () => {
    const p = pipeline();
    await expect(p.svc.ingest({ ...base, timestamp: 'garbage' } as any, ctx)).rejects.toThrow(new BadRequestException('Invalid timestamp'));
    expect(p.created).toHaveLength(0);
  });

  it('rejects a timestamp in the future, but tolerates small clock differences', async () => {
    const p = pipeline();
    const far = new Date(Date.now() + 3600_000).toISOString();
    await expect(p.svc.ingest({ ...base, timestamp: far } as any, ctx)).rejects.toThrow('Timestamp is in the future');
    const near = new Date(Date.now() + 60_000).toISOString();
    await expect(p.svc.ingest({ ...base, timestamp: near } as any, ctx)).resolves.toBeDefined();
    expect(p.created).toHaveLength(1);
  });

  it('accepts old events, so a website can send a delayed batch', async () => {
    const p = pipeline();
    await expect(p.svc.ingest({ ...base, timestamp: '2020-01-01T00:00:00Z' } as any, ctx)).resolves.toBeDefined();
  });

  it('still accepts the event when address tracking fails', async () => {
    const p = pipeline({ touch: () => { throw new Error('db down'); } });
    const r = await p.svc.ingest(base as any, ctx);
    expect(r.id).toBe('e1');
    expect(p.detection.processEvent).toHaveBeenCalled();
  });

  it('still accepts the event when detection fails, reports a neutral result, and still audits', async () => {
    const p = pipeline({ detect: () => { throw new Error('rule crashed'); } });
    const r = await p.svc.ingest(base as any, ctx);
    expect(r).toEqual({ id: 'e1', riskScore: 0, riskLevel: 'NORMAL', incidentId: null });
    expect(p.audit.log).toHaveBeenCalled();
  });
});

describe('EventsService.ingest idempotency', () => {
  const withId = { ...base, event_id: 'evt-0123456789abcdef' };

  it('stores an event with an id once, however many times it is delivered', async () => {
    const p = pipeline();
    const first = await p.svc.ingest(withId as any, ctx);
    const again = await p.svc.ingest(withId as any, ctx);
    const third = await p.svc.ingest(withId as any, ctx);
    expect(p.created).toHaveLength(1);
    expect(first.id).toBe('e1');
    expect(again).toEqual({ id: 'e1', riskScore: 40, riskLevel: 'SUSPICIOUS', incidentId: 'inc1', duplicate: true });
    expect(third.id).toBe('e1');
  });

  it('does not run detection, touch the address or audit a second time for a repeat', async () => {
    const p = pipeline();
    await p.svc.ingest(withId as any, ctx);
    await p.svc.ingest(withId as any, ctx);
    expect(p.detection.processEvent).toHaveBeenCalledTimes(1);
    expect(p.ips.touch).toHaveBeenCalledTimes(1);
    expect(p.audit.log).toHaveBeenCalledTimes(1);
  });

  it('keeps ids separate per API key, so one sender can never collide with or read another', async () => {
    const p = pipeline();
    await p.svc.ingest(withId as any, { ...ctx, apiKeyId: 'k1' });
    await p.svc.ingest(withId as any, { ...ctx, apiKeyId: 'k2' });
    expect(p.created).toHaveLength(2);
  });

  it('treats events without an id as separate events, as before', async () => {
    const p = pipeline();
    await p.svc.ingest(base as any, ctx);
    await p.svc.ingest(base as any, ctx);
    expect(p.created).toHaveLength(2);
    expect(p.created[0].externalId).toBeUndefined();
  });

  it('different ids are different events', async () => {
    const p = pipeline();
    await p.svc.ingest({ ...base, event_id: 'a' } as any, ctx);
    await p.svc.ingest({ ...base, event_id: 'b' } as any, ctx);
    expect(p.created).toHaveLength(2);
  });

  it('two copies arriving at the same moment end up as one event, and both get the same answer', async () => {
    const p = pipeline({ raceOnCreate: true });
    const r = await p.svc.ingest(withId as any, ctx);
    expect(r).toEqual({ id: 'winner', riskScore: 55, riskLevel: 'SUSPICIOUS', incidentId: 'incW', duplicate: true });
    expect(p.detection.processEvent).not.toHaveBeenCalled();
  });

  it('a genuine database failure is not mistaken for a repeat', async () => {
    const p = pipeline();
    (p.svc as any).prisma.securityEvent.create = async () => { throw new Error('disk full'); };
    await expect(p.svc.ingest(withId as any, ctx)).rejects.toThrow('disk full');
  });

  it('the id is validated: short, plain characters only', async () => {
    const errors = async (id: any) => (await validate(plainToInstance(CreateEventDto, { event_type: 'x', severity: 'LOW', event_id: id }))).map((e) => e.property);
    expect(await errors('abc-123_DEF.9:x')).toEqual([]);
    expect(await errors('has space')).toContain('event_id');
    expect(await errors('x'.repeat(65))).toContain('event_id');
    expect(await errors('<script>')).toContain('event_id');
  });
});

describe('EventsService.list', () => {
  function listing() {
    const seen: any = {};
    const prisma: any = { securityEvent: {
      findMany: async (a: any) => { seen.find = a; return []; },
      count: async (a: any) => { seen.count = a; return 0; },
    } };
    return { seen, svc: new EventsService(prisma, {} as any, {} as any, {} as any) };
  }
  const page = { page: 1, pageSize: 25, skip: 0, take: 25, sortBy: 'occurredAt', sortOrder: 'desc' as const };

  it('builds filters, normalizing the address', async () => {
    const { svc, seen } = listing();
    await svc.list({ ...page, filters: { eventType: 'login_failed', ipAddress: '::ffff:198.51.100.7', from: '2026-10-01T00:00:00Z' } });
    expect(seen.find.where).toMatchObject({ eventType: 'login_failed', ipAddress: '198.51.100.7' });
    expect(seen.find.where.occurredAt.gte.toISOString()).toBe('2026-10-01T00:00:00.000Z');
    expect(seen.find.orderBy).toEqual({ occurredAt: 'desc' });
  });

  it('rejects an invalid date with a 400 instead of failing in the database', async () => {
    await expect(listing().svc.list({ ...page, filters: { from: 'yesterday-ish' } })).rejects.toThrow('Invalid from date');
    await expect(listing().svc.list({ ...page, filters: { to: 'nope' } })).rejects.toThrow('Invalid to date');
  });
});

describe('CreateEventDto', () => {
  const errors = async (o: any) => (await validate(plainToInstance(CreateEventDto, o))).map((e) => e.property);
  const ok = { event_type: 'login_failed', severity: 'HIGH' };

  it('accepts a minimal and a full event', async () => {
    expect(await errors(ok)).toEqual([]);
    expect(await errors({ ...ok, ip_address: '1.2.3.4', user_id: 'u', session_id: 's', user_agent: 'ua', request_method: 'POST',
      request_path: '/login', request_id: 'r', metadata: { a: 1 }, timestamp: '2026-10-02T10:00:00Z' })).toEqual([]);
  });
  it('requires an event type and a known severity', async () => {
    expect(await errors({ severity: 'HIGH' })).toContain('event_type');
    expect(await errors({ event_type: 'x', severity: 'URGENT' })).toContain('severity');
    expect(await errors({ event_type: 'x' })).toContain('severity');
  });
  it('limits field sizes', async () => {
    expect(await errors({ ...ok, ip_address: 'x'.repeat(46) })).toContain('ip_address');
    expect(await errors({ ...ok, request_path: 'x'.repeat(1025) })).toContain('request_path');
    expect(await errors({ ...ok, user_agent: 'x'.repeat(513) })).toContain('user_agent');
    expect(await errors({ ...ok, event_type: 'x'.repeat(65) })).toContain('event_type');
  });
  it('rejects a bad timestamp and a non-object metadata', async () => {
    expect(await errors({ ...ok, timestamp: 'tomorrow' })).toContain('timestamp');
    expect(await errors({ ...ok, metadata: 'text' })).toContain('metadata');
  });
});
