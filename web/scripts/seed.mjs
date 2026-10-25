/**
 * Bootstrap tables + first super admin + website API key.
 * Usage: node --env-file=.env scripts/seed.mjs
 */
import { createClient } from '@libsql/client';
import { createHash, randomBytes } from 'crypto';
import { hashSync } from 'bcryptjs';
import { mkdirSync } from 'fs';
import { dirname } from 'path';

const url = process.env.DATABASE_URL || 'file:./data/ir.db';
if (url.startsWith('file:')) {
  try { mkdirSync(dirname(url.replace('file:', '')), { recursive: true }); } catch { /* */ }
}
const authToken = process.env.DATABASE_AUTH_TOKEN;
const pepper = process.env.API_KEY_HASH_PEPPER;
if (!pepper || pepper.length < 16) {
  console.error('Set API_KEY_HASH_PEPPER in .env (at least 16 characters)');
  process.exit(1);
}
const prefix = process.env.API_KEY_PREFIX || 'IRS_';
const client = createClient({ url, authToken: authToken || undefined });

const id = () => randomBytes(16).toString('hex');

const DDL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'VIEWER', is_active INTEGER NOT NULL DEFAULT 1,
  must_change_password INTEGER NOT NULL DEFAULT 0, token_version INTEGER NOT NULL DEFAULT 0,
  password_changed_at INTEGER, last_login_at INTEGER, totp_secret TEXT, totp_enabled_at INTEGER,
  totp_last_step INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, code_hash TEXT NOT NULL UNIQUE,
  used_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL, session_started_at INTEGER, last_used_at INTEGER,
  device_label TEXT, ip_address TEXT, user_agent TEXT, expires_at INTEGER,
  revoked_at INTEGER, revoked_reason TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'events:write', is_active INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER, created_by TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, api_key_id TEXT, external_id TEXT, event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'INFO', ip_address TEXT, user_id TEXT, session_id TEXT,
  user_agent TEXT, request_method TEXT, request_path TEXT, request_id TEXT, metadata TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0, risk_level TEXT NOT NULL DEFAULT 'NORMAL',
  matched_rules TEXT, incident_id TEXT, occurred_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE UNIQUE INDEX IF NOT EXISTS events_api_external_uidx ON events(api_key_id, external_id);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, public_number INTEGER NOT NULL, title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN', severity TEXT NOT NULL DEFAULT 'MEDIUM',
  source_ip TEXT, user_id TEXT, open_key TEXT, risk_score INTEGER NOT NULL DEFAULT 0,
  assigned_to TEXT, summary TEXT, event_count INTEGER NOT NULL DEFAULT 0,
  resolved_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_public_number_uidx ON incidents(public_number);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_key_uidx ON incidents(open_key);
CREATE TABLE IF NOT EXISTS ip_blocks (
  id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, action TEXT NOT NULL DEFAULT 'BLOCK',
  reason TEXT NOT NULL, administrator_id TEXT, related_incident_id TEXT,
  is_permanent INTEGER NOT NULL DEFAULT 0, expires_at INTEGER, active INTEGER NOT NULL DEFAULT 1,
  automatic INTEGER NOT NULL DEFAULT 0, active_key TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE UNIQUE INDEX IF NOT EXISTS ip_blocks_active_key_uidx ON ip_blocks(active_key);
CREATE TABLE IF NOT EXISTS allowlist (
  id TEXT PRIMARY KEY, ip_address TEXT NOT NULL UNIQUE, reason TEXT NOT NULL,
  added_by TEXT, expires_at INTEGER, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS ip_intelligence (
  id TEXT PRIMARY KEY, ip_address TEXT NOT NULL UNIQUE, first_seen_at INTEGER, last_seen_at INTEGER,
  request_count INTEGER NOT NULL DEFAULT 0, event_count INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0, risk_score INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL DEFAULT 'NORMAL', country TEXT, region TEXT, city TEXT,
  is_vpn INTEGER NOT NULL DEFAULT 0, is_proxy INTEGER NOT NULL DEFAULT 0, is_tor INTEGER NOT NULL DEFAULT 0,
  is_datacenter INTEGER NOT NULL DEFAULT 0, is_malicious INTEGER NOT NULL DEFAULT 0,
  reputation_score INTEGER NOT NULL DEFAULT 0, last_intel_update INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, request_id TEXT, actor_type TEXT NOT NULL, actor_id TEXT, actor_label TEXT,
  action TEXT NOT NULL, target_type TEXT, target_id TEXT, result TEXT NOT NULL DEFAULT 'SUCCESS',
  metadata TEXT, ip_address TEXT, user_agent TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS login_throttle (
  key_hash TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, locked_until INTEGER,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);
CREATE TABLE IF NOT EXISTS detection_rules (
  code TEXT PRIMARY KEY, is_enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100,
  config TEXT NOT NULL DEFAULT '{}', updated_at INTEGER
);
`;

async function main() {
  await client.executeMultiple(DDL);
  const email = (process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@example.com').toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || randomBytes(12).toString('base64url');
  const existing = await client.execute({ sql: 'SELECT id FROM users WHERE email = ?', args: [email] });
  if (existing.rows.length === 0) {
    await client.execute({
      sql: `INSERT INTO users (id, email, name, password_hash, role, must_change_password, created_at)
            VALUES (?, ?, ?, ?, 'SUPER_ADMIN', 1, ?)`,
      args: [id(), email, 'Initial Admin', hashSync(password, 12), Date.now()],
    });
    console.log('Admin:', email);
    console.log('Password:', password);
  } else {
    console.log('Admin already exists:', email);
  }

  const lookup = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('base64url');
  const keyPrefix = `${prefix}${lookup}`;
  const raw = `${keyPrefix}${secret}`;
  const keyHash = createHash('sha256').update(raw + pepper).digest('hex');
  await client.execute({
    sql: `INSERT INTO api_keys (id, name, key_prefix, key_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [id(), 'Website', keyPrefix, keyHash, 'events:write,block:read', Date.now()],
  });
  console.log('API key (save once):', raw);
}

main().catch((e) => { console.error(e); process.exit(1); });
