/**
 * SQLite integration tests against an isolated temp database.
 * Run: npm test (vitest)
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
import { createClient } from '@libsql/client';
import { createHash } from 'crypto';
import { hashSync } from 'bcryptjs';

const tmp = mkdtempSync(join(tmpdir(), 'ir-int-'));
const dbPath = join(tmp, 'test.db');
const dbUrl = `file:${dbPath}`;

// Must set env before importing app modules that read it at load time.
process.env.DATABASE_URL = dbUrl;
process.env.DATABASE_AUTH_TOKEN = '';
process.env.JWT_SECRET = 'integration-test-jwt-secret-at-least-32-chars';
process.env.JWT_REFRESH_SECRET = 'integration-test-refresh-secret-32chars!!';
process.env.API_KEY_HASH_PEPPER = 'integration-pepper-16';
process.env.API_KEY_PREFIX = 'IRS_';
process.env.REQUIRE_2FA = 'false';
process.env.NODE_ENV = 'test';

// Force a fresh db singleton after env is set.
delete (globalThis as unknown as { __irDb?: unknown }).__irDb;

async function applyMigration() {
  const client = createClient({ url: dbUrl });
  const sql = readFileSync(join(__dirname, '../../../drizzle/0000_initial/migration.sql'), 'utf8');
  await client.executeMultiple(sql);
  client.close();
}

describe('SQLite integration', () => {
  let db: typeof import('../db/client').db;
  let generateApiKey: typeof import('../auth/crypto').generateApiKey;
  let newId: typeof import('../auth/crypto').newId;
  let ingestEvent: typeof import('../services/events').ingestEvent;
  let verifyApiKey: typeof import('../services/events').verifyApiKey;
  let listActiveBlocks: typeof import('../services/events').listActiveBlocks;
  let loginWithPassword: typeof import('../auth/session').loginWithPassword;
  let listRules: typeof import('../services/rules').listRules;
  let updateRule: typeof import('../services/rules').updateRule;
  let apiKeys: typeof import('../db/schema').apiKeys;
  let users: typeof import('../db/schema').users;
  let eq: typeof import('drizzle-orm').eq;

  beforeAll(async () => {
    await applyMigration();
    delete (globalThis as unknown as { __irDb?: unknown }).__irDb;
    const clientMod = await import('../db/client');
    db = clientMod.db;
    const crypto = await import('../auth/crypto');
    generateApiKey = crypto.generateApiKey;
    newId = crypto.newId;
    const events = await import('../services/events');
    ingestEvent = events.ingestEvent;
    verifyApiKey = events.verifyApiKey;
    listActiveBlocks = events.listActiveBlocks;
    const session = await import('../auth/session');
    loginWithPassword = session.loginWithPassword;
    const rules = await import('../services/rules');
    listRules = rules.listRules;
    updateRule = rules.updateRule;
    const schema = await import('../db/schema');
    apiKeys = schema.apiKeys;
    users = schema.users;
    eq = (await import('drizzle-orm')).eq;

    // Seed admin + API key
    const adminId = newId();
    await db.insert(users).values({
      id: adminId,
      email: 'admin@test.local',
      name: 'Admin',
      passwordHash: hashSync('TestPassword1', 12),
      role: 'SUPER_ADMIN',
      isActive: true,
      mustChangePassword: false,
      tokenVersion: 0,
      createdAt: new Date(),
    });

    const generated = generateApiKey('IRS_');
    await db.insert(apiKeys).values({
      id: newId(),
      name: 'test-site',
      keyPrefix: generated.prefix,
      keyHash: generated.hash,
      scopes: 'events:write,block:read',
      isActive: true,
      createdAt: new Date(),
    });
    // stash raw key for tests
    (globalThis as unknown as { __testApiKey?: string }).__testApiKey = generated.raw;
  }, 60_000);

  afterAll(() => {
    try {
      rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  it('applies schema so users table is queryable', async () => {
    const rows = await db.select().from(users);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[0].email).toBe('admin@test.local');
  });

  it('verifies a valid API key and rejects a bad one', async () => {
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const ok = await verifyApiKey(raw);
    expect(ok).not.toBeNull();
    expect(ok!.name).toBe('test-site');

    const bad = await verifyApiKey(raw.slice(0, -4) + 'xxxx');
    expect(bad).toBeNull();
  });

  it('logs in with correct password', async () => {
    const outcome = await loginWithPassword('admin@test.local', 'TestPassword1', {});
    expect(outcome.kind).toBe('session');
    if (outcome.kind === 'session') {
      expect(outcome.accessToken).toBeTruthy();
      expect(outcome.user.email).toBe('admin@test.local');
    }
  });

  it('rejects wrong password', async () => {
    await expect(loginWithPassword('admin@test.local', 'WrongPassword1', {})).rejects.toMatchObject({
      status: 401,
    });
  });

  it('ingests an event and opens an incident for elevated risk', async () => {
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const key = await verifyApiKey(raw);
    expect(key).not.toBeNull();

    const result = await ingestEvent(key!.id, {
      event_type: 'suspicious_request',
      severity: 'HIGH',
      ip_address: '203.0.113.50',
      event_id: 'evt-integration-1',
    });

    expect(result.duplicate).toBe(false);
    expect(result.riskScore).toBeGreaterThanOrEqual(40);
    expect(result.incidentId).toBeTruthy();
  });

  it('is idempotent on the same event_id', async () => {
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const key = await verifyApiKey(raw);
    const second = await ingestEvent(key!.id, {
      event_type: 'suspicious_request',
      severity: 'HIGH',
      ip_address: '203.0.113.50',
      event_id: 'evt-integration-1',
    });
    expect(second.duplicate).toBe(true);
  });

  it('auto-blocks when risk reaches threshold', async () => {
    await updateRule('auto_block', { isEnabled: true, config: { threshold: 50, blockMinutes: 30 } });
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const key = await verifyApiKey(raw);
    const result = await ingestEvent(key!.id, {
      event_type: 'payment_security_event',
      severity: 'CRITICAL',
      ip_address: '203.0.113.99',
      event_id: 'evt-autoblock-1',
    });
    expect(result.riskScore).toBeGreaterThanOrEqual(50);
    const blocks = await listActiveBlocks();
    expect(blocks.find((b) => b.ipAddress === '203.0.113.99')).toBeTruthy();
    // restore default-ish threshold
    await updateRule('auto_block', { config: { threshold: 85, blockMinutes: 60 } });
  });

  it('does not block private IPs', async () => {
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const key = await verifyApiKey(raw);
    await ingestEvent(key!.id, {
      event_type: 'payment_security_event',
      severity: 'CRITICAL',
      ip_address: '10.0.0.5',
      event_id: 'evt-private-1',
    });
    await ingestEvent(key!.id, {
      event_type: 'suspicious_request',
      severity: 'CRITICAL',
      ip_address: '10.0.0.5',
      event_id: 'evt-private-2',
    });
    const blocks = await listActiveBlocks();
    expect(blocks.find((b) => b.ipAddress === '10.0.0.5')).toBeUndefined();
  });

  it('lists default rules and can disable one', async () => {
    const before = await listRules();
    expect(before.length).toBeGreaterThan(0);
    const code = 'login_failed';
    await updateRule(code, { isEnabled: false });
    const after = await listRules();
    const rule = after.find((r) => r.code === code);
    expect(rule?.isEnabled).toBe(false);
    // restore
    await updateRule(code, { isEnabled: true });
  });

  it('stores API key hash, never the raw secret', async () => {
    const raw = (globalThis as unknown as { __testApiKey: string }).__testApiKey;
    const rows = await db.select().from(apiKeys);
    for (const row of rows) {
      expect(row.keyHash).not.toContain(raw);
      expect(row.keyHash).toHaveLength(64); // sha256 hex
    }
  });
});
