import 'reflect-metadata';
import { ExecutionContext, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Controller, Get, Post } from '@nestjs/common';
import { Throttle, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import request from 'supertest';
import { AppThrottlerGuard, apiKeyToken } from '../src/common/guards/app-throttler.guard';

process.env.API_KEY_PREFIX = 'PMS_';

@Controller('t')
class Probe {
  @Post('events') events() { return { ok: true }; }
  @Get('admin') admin() { return { ok: true }; }
  @Throttle({ ip: { limit: 3, ttl: 60000 } })
  @Post('login') login() { return { ok: true }; }
}

describe('rate limiting', () => {
  let app: INestApplication;
  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      imports: [ThrottlerModule.forRoot([
        { name: 'ip', ttl: 60000, limit: 5 },
        { name: 'key', ttl: 60000, limit: 50 },
      ])],
      controllers: [Probe],
      providers: [{ provide: APP_GUARD, useClass: AppThrottlerGuard }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();
  });
  afterAll(() => app.close());
  const http = () => request(app.getHttpServer());
  const statuses = async (n: number, make: () => request.Test) => {
    const out: number[] = [];
    for (let i = 0; i < n; i++) out.push((await make()).status);
    return out;
  };

  it('limits an anonymous caller by address', async () => {
    const s = await statuses(7, () => http().get('/t/admin'));
    expect(s.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(s.slice(5)).toEqual([429, 429]);
  });

  it('gives the website a far larger allowance than a person, counted per key', async () => {
    const s = await statuses(40, () => http().post('/t/events').set('Authorization', 'Bearer PMS_aaaaaaaaaaaaaaaaaaaaaaaaaaaa1'));
    expect(s.every((x) => x === 201)).toBe(true);
  });

  it('still bounds a key, so a leaked key cannot flood the system', async () => {
    const s = await statuses(60, () => http().post('/t/events').set('Authorization', 'Bearer PMS_bbbbbbbbbbbbbbbbbbbbbbbbbbbb2'));
    expect(s.filter((x) => x === 429).length).toBe(10);
  });

  it('counts each key separately', async () => {
    const a = await http().post('/t/events').set('Authorization', 'Bearer PMS_cccccccccccccccccccccccccccc3');
    const b = await http().post('/t/events').set('Authorization', 'Bearer PMS_dddddddddddddddddddddddddddd4');
    expect([a.status, b.status]).toEqual([201, 201]);
  });

  it('a busy website does not use up an administrator\'s allowance, and the reverse', async () => {
    await statuses(30, () => http().post('/t/events').set('Authorization', 'Bearer PMS_eeeeeeeeeeeeeeeeeeeeeeeeeeee5'));
    const r = await http().post('/t/events').set('Authorization', 'Bearer eyJ.admin.jwt');
    expect(r.status).toBe(201);
  });

  it('gives sign-in its own small allowance per address', async () => {
    const s = await statuses(5, () => http().post('/t/login'));
    expect(s).toEqual([201, 201, 201, 429, 429]);
  });

  it('tells a refused caller when to try again, under the standard header name', async () => {
    // The sign-in allowance was used up by the previous test, so this call is refused.
    const refused = await http().post('/t/login');
    expect(refused.status).toBe(429);
    const seconds = Number(refused.headers['retry-after']);
    expect(seconds).toBeGreaterThanOrEqual(1);
    expect(seconds).toBeLessThanOrEqual(60);
  });

  it('a token that merely looks like a key prefix is not special-cased unless it starts with it', () => {
    expect(apiKeyToken({ headers: { authorization: 'Bearer PMS_x' } })).toBe('PMS_x');
    expect(apiKeyToken({ headers: { authorization: 'Bearer eyJhbGciOi' } })).toBeNull();
    expect(apiKeyToken({ headers: { authorization: 'PMS_x' } })).toBeNull();
    expect(apiKeyToken({ headers: {} })).toBeNull();
    expect(apiKeyToken({})).toBeNull();
  });
});
