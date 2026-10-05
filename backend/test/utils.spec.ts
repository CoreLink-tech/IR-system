import 'reflect-metadata';
import { ArgumentsHost, BadRequestException, HttpException, NotFoundException } from '@nestjs/common';
import { of } from 'rxjs';
import { parseDateParam, parsePagination, toPaginated } from '../src/common/utils/pagination.util';
import { extractIp, isInternalAddress, isPrivateIp, normalizeIp } from '../src/common/utils/ip.util';
import { generateApiKey, hashApiKey, safeEqual, sha256 } from '../src/common/utils/crypto.util';
import { clampScore, riskLevelFor, riskThresholds } from '../src/common/utils/risk.util';
import { AllExceptionsFilter } from '../src/common/filters/http-exception.filter';
import { RequestIdInterceptor } from '../src/common/interceptors/request-id.interceptor';
import { AuditService } from '../src/audit/audit.service';

describe('parsePagination', () => {
  it('applies sensible defaults', () => {
    expect(parsePagination({})).toEqual({ page: 1, pageSize: 25, skip: 0, take: 25, sortBy: 'createdAt', sortOrder: 'desc' });
  });
  it('computes skip from page and size', () => {
    expect(parsePagination({ page: '3', pageSize: '10' })).toMatchObject({ page: 3, pageSize: 10, skip: 20, take: 10 });
  });
  it('clamps size to 1..200 and page to at least 1, and survives junk', () => {
    expect(parsePagination({ pageSize: 9999 }).pageSize).toBe(200);
    expect(parsePagination({ pageSize: -5 }).pageSize).toBe(25);
    expect(parsePagination({ pageSize: 0 }).pageSize).toBe(25);
    expect(parsePagination({ pageSize: 10.9 }).pageSize).toBe(10);
    expect(parsePagination({ page: 0 }).page).toBe(1);
    expect(parsePagination({ page: 'abc', pageSize: 'xyz' })).toMatchObject({ page: 1, pageSize: 25 });
  });
  it('sorts ascending only when asked, never by injected values', () => {
    expect(parsePagination({ sortOrder: 'asc' }).sortOrder).toBe('asc');
    expect(parsePagination({ sortOrder: 'DROP' as any }).sortOrder).toBe('desc');
  });
  it('falls back to the default when sortBy is not on the allowed list', () => {
    const d = { sortBy: 'createdAt', allowedSort: ['createdAt', 'severity'] };
    expect(parsePagination({ sortBy: 'severity' }, d).sortBy).toBe('severity');
    expect(parsePagination({ sortBy: 'passwordHash' }, d).sortBy).toBe('createdAt');
    expect(parsePagination({ sortBy: ['x'] as any }, d).sortBy).toBe('createdAt');
  });
  it('wraps results with totals', () => {
    expect(toPaginated([1, 2], 51, 2, 25)).toEqual({ data: [1, 2], meta: { page: 2, pageSize: 25, total: 51, totalPages: 3 } });
    expect(toPaginated([], 0, 1, 25).meta.totalPages).toBe(1);
  });
});

describe('parseDateParam', () => {
  it('returns undefined for absent values and a Date for valid ones', () => {
    expect(parseDateParam(undefined, 'from')).toBeUndefined();
    expect(parseDateParam('', 'from')).toBeUndefined();
    expect(parseDateParam('2026-10-02T10:00:00Z', 'from')!.toISOString()).toBe('2026-10-02T10:00:00.000Z');
  });
  it('rejects an invalid date with a 400 that names the parameter', () => {
    expect(() => parseDateParam('soon', 'to')).toThrow(new BadRequestException('Invalid to date'));
  });
});

describe('IP utilities', () => {
  it('normalizes valid addresses and rejects invalid ones', () => {
    expect(normalizeIp(' 198.51.100.7 ')).toBe('198.51.100.7');
    expect(normalizeIp('::ffff:198.51.100.7')).toBe('198.51.100.7');
    expect(normalizeIp('2001:DB8::1')).toBe('2001:db8::1');
    for (const bad of ['', undefined, null, 'abc', '999.1.1.1', '1.2.3', '1.2.3.4.5', '<script>']) expect(normalizeIp(bad as any)).toBeUndefined();
  });

  it('refuses shorthand, hexadecimal and octal forms that would mean a different address', () => {
    for (const tricky of ['127.1', '1.2.3', '0x7f.0.0.1', '0x7f000001', '2130706433', '010.0.0.1', '1.2.3.04', '08.8.8.8', '1.1.1.1.', ' ']) {
      expect(normalizeIp(tricky)).toBeUndefined();
    }
    expect(normalizeIp('127.0.0.1')).toBe('127.0.0.1');
    expect(normalizeIp('0.0.0.0')).toBe('0.0.0.0');
  });

  it('knows which addresses are private or reserved', () => {
    for (const ip of ['10.0.0.1', '172.16.5.5', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1', 'fe80::1', '0.0.0.0']) {
      expect(isPrivateIp(ip)).toBe(true);
    }
    for (const ip of ['1.1.1.1', '8.8.8.8', '198.51.100.7'.replace('198.51.100.7', '104.16.0.1'), '2606:4700::1111']) {
      expect(isPrivateIp(ip)).toBe(false);
    }
    expect(isPrivateIp('not-an-ip')).toBe(false);
  });

  it('flags addresses that must never be blocked', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.9', '172.20.0.1', '169.254.0.5', '100.64.0.1', '::1', 'fe80::1', 'fc00::1', '0.0.0.0']) {
      expect(isInternalAddress(ip)).toBe(true);
    }
    for (const ip of ['1.1.1.1', '104.16.0.1', '2606:4700::1111']) expect(isInternalAddress(ip)).toBe(false);
    expect(isInternalAddress('junk')).toBe(false);
  });

  it('extracts the client address from forwarding headers, then the socket', () => {
    const req = (headers: any, remote?: string): any => ({ headers, socket: { remoteAddress: remote } });
    expect(extractIp(req({ 'x-forwarded-for': '203.0.113.5, 10.0.0.1' }))).toBe('203.0.113.5');
    expect(extractIp(req({ 'x-real-ip': '203.0.113.6' }))).toBe('203.0.113.6');
    expect(extractIp(req({}, '::ffff:203.0.113.7'))).toBe('203.0.113.7');
    expect(extractIp(req({ 'x-forwarded-for': 'garbage' }, '203.0.113.8'))).toBe('203.0.113.8');
    expect(extractIp(req({}, undefined))).toBeUndefined();
  });
});

describe('crypto utilities', () => {
  beforeAll(() => { process.env.API_KEY_HASH_PEPPER = 'pepper-1'; });

  it('hashes deterministically and depends on the pepper', () => {
    const a = hashApiKey('PMS_abc');
    expect(hashApiKey('PMS_abc')).toBe(a);
    process.env.API_KEY_HASH_PEPPER = 'pepper-2';
    expect(hashApiKey('PMS_abc')).not.toBe(a);
    process.env.API_KEY_HASH_PEPPER = 'pepper-1';
  });
  it('generates unique keys whose stored prefix leads the raw key', () => {
    const k1 = generateApiKey('PMS_'); const k2 = generateApiKey('PMS_');
    expect(k1.raw).not.toBe(k2.raw);
    expect(k1.raw.startsWith(k1.prefix)).toBe(true);
    expect(k1.prefix).toHaveLength(4 + 16);
    expect(k1.hash).toBe(hashApiKey(k1.raw));
    expect(k1.raw.length).toBeGreaterThan(50);
  });
  it('compares strings in constant time and rejects different lengths', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('', '')).toBe(true);
  });
  it('has a plain sha256', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('risk utilities', () => {
  it('rates scores at the documented boundaries', () => {
    const t = riskThresholds();
    expect(riskLevelFor(0)).toBe('NORMAL');
    expect(riskLevelFor(t.suspicious - 1)).toBe('NORMAL');
    expect(riskLevelFor(t.suspicious)).toBe('SUSPICIOUS');
    expect(riskLevelFor(t.high)).toBe('HIGH');
    expect(riskLevelFor(t.critical)).toBe('CRITICAL');
    expect(riskLevelFor(100)).toBe('CRITICAL');
  });
  it('clamps scores to 0..100 and rounds', () => {
    expect(clampScore(-20)).toBe(0);
    expect(clampScore(250)).toBe(100);
    expect(clampScore(41.6)).toBe(42);
  });
});

function host(req: any = {}) {
  const res: any = { statusCode: 0, body: undefined, status(c: number) { this.statusCode = c; return this; }, json(b: any) { this.body = b; return this; } };
  const h = { switchToHttp: () => ({ getResponse: () => res, getRequest: () => ({ url: '/x', method: 'GET', requestId: 'r1', ...req }) }) } as unknown as ArgumentsHost;
  return { h, res };
}

describe('AllExceptionsFilter', () => {
  it('turns an HTTP exception into a JSON body with the request id', () => {
    const { h, res } = host();
    new AllExceptionsFilter().catch(new NotFoundException('Incident not found'), h);
    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject({ statusCode: 404, message: 'Incident not found', path: '/x', method: 'GET', requestId: 'r1' });
  });
  it('keeps validation messages as a list', () => {
    const { h, res } = host();
    new AllExceptionsFilter().catch(new BadRequestException(['a must be a string', 'b is required']), h);
    expect(res.body.message).toEqual(['a must be a string', 'b is required']);
  });
  it('hides the details of unexpected errors from the caller', () => {
    const { h, res } = host();
    new AllExceptionsFilter().catch(new Error('connection to db at 10.0.0.5 failed: password authentication'), h);
    expect(res.statusCode).toBe(500);
    expect(res.body.message).toBe('Internal server error');
    expect(JSON.stringify(res.body)).not.toContain('10.0.0.5');
  });
  it('handles non-Error throws and string responses', () => {
    const a = host(); new AllExceptionsFilter().catch('boom', a.h);
    expect(a.res.statusCode).toBe(500);
    const b = host(); new AllExceptionsFilter().catch(new HttpException('teapot', 418), b.h);
    expect(b.res.body).toMatchObject({ statusCode: 418, message: 'teapot' });
  });
});

describe('RequestIdInterceptor', () => {
  const run = (headers: any) => {
    const req: any = { headers }; const res: any = { headers: {} as any, setHeader(k: string, v: string) { this.headers[k] = v; } };
    const ctx: any = { switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }) };
    new RequestIdInterceptor().intercept(ctx, { handle: () => of(1) });
    return { req, res };
  };
  it('keeps a caller supplied request id and echoes it back', () => {
    const { req, res } = run({ 'x-request-id': 'abc-123' });
    expect(req.requestId).toBe('abc-123');
    expect(res.headers['X-Request-Id']).toBe('abc-123');
  });
  it('generates an id when none is supplied', () => {
    const { req, res } = run({});
    expect(req.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.headers['X-Request-Id']).toBe(req.requestId);
  });
});

describe('AuditService', () => {
  it('writes the entry, linking the user only for user actors', async () => {
    const create = jest.fn(async ({ data }: any) => data);
    const svc = new AuditService({ securityAuditLog: { create } } as any);
    await svc.log({ actorType: 'USER', actorId: 'u1', action: 'x', result: 'SUCCESS', metadata: { a: 1 } });
    await svc.log({ actorType: 'API_KEY', actorId: 'k1', action: 'y', result: 'SUCCESS' });
    expect(create.mock.calls[0][0].data).toMatchObject({ userId: 'u1', metadata: { a: 1 } });
    expect(create.mock.calls[1][0].data.userId).toBeUndefined();
  });
  it('never lets an audit failure break the request', async () => {
    const svc = new AuditService({ securityAuditLog: { create: async () => { throw new Error('db down'); } } } as any);
    await expect(svc.log({ actorType: 'SYSTEM', action: 'x', result: 'SUCCESS' })).resolves.toBeNull();
  });
});

describe('shared address vectors (the PHP client must agree with these exactly)', () => {
  const file = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '../../integration/shared/ip-vectors.json'), 'utf8'));

  it('has a meaningful number of cases', () => {
    expect(file.vectors.length).toBeGreaterThan(80);
  });

  it.each(file.vectors.map((v: any) => [JSON.stringify(v.input), v]))('normalizes %s', (_name: string, v: any) => {
    expect(normalizeIp(v.input) ?? null).toBe(v.normalized);
    if (v.normalized) expect(isInternalAddress(v.normalized)).toBe(v.internal);
  });
});
